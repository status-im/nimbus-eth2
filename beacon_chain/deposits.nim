# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[os, sequtils, times],
  stew/byteutils,
  chronicles,
  ./spec/eth2_apis/rest_beacon_client,
  ./spec/signatures,
  ./validators/keystore_management,
  "."/[conf, beacon_clock, filepath]

type
  ValidatorStorageKind* {.pure.} = enum
    Keystore, Identifier

  ValidatorStorage* = object
    case kind: ValidatorStorageKind
    of ValidatorStorageKind.Keystore:
      privateKey: ValidatorPrivKey
    of ValidatorStorageKind.Identifier:
      ident: ValidatorIdent

proc getSignedExitMessage(
       config: BeaconNodeConf,
       storage: ValidatorStorage,
       validatorKeyAsStr: string,
       exitAtEpoch: Epoch,
       validatorIdx: uint64,
       fork: Fork,
       genesis_validators_root: Eth2Digest
     ): SignedVoluntaryExit =

  let signingKey =
    case storage.kind
    of ValidatorStorageKind.Identifier:
      let
        validatorsDir = config.validatorsDir
        keystoreDir = validatorsDir / validatorKeyAsStr

      if not dirExists(keystoreDir):
        echo "The validator keystores directory '" & validatorsDir &
             "' does not contain a keystore for the selected validator " &
             "with public key '" & validatorKeyAsStr & "'."
        quit 1

      let signingItem = loadKeystore(
        validatorsDir,
        config.secretsDir,
        validatorKeyAsStr,
        config.nonInteractive,
        nil)

      if signingItem.isNone:
        fatal "Unable to continue without decrypted signing key"
        quit 1

      signingItem.get().privateKey

    of ValidatorStorageKind.Keystore:
      storage.privateKey

  var signedExit = SignedVoluntaryExit(
    message: VoluntaryExit(
      epoch: exitAtEpoch,
      validator_index: validatorIdx
    )
  )

  signedExit.signature =
    get_voluntary_exit_signature(fork, genesis_validators_root,
                                 signedExit.message,
                                 signingKey).toValidatorSig()
  signedExit

type
  ClientExitAction = enum
    quiting = "q"
    confirmation = "I understand the implications of submitting a voluntary exit"

proc askForExitConfirmation(): ClientExitAction =
  template ask(prompt: string): string =
    try:
      stdout.write prompt, ": "
      stdin.readLine()
    except IOError:
      fatal "Failed to read user input from stdin"
      quit 1

  echoP "PLEASE BEWARE!"

  echoP "Publishing a voluntary exit is an irreversible operation! " &
        "You won't be able to restart again with the same validator."

  echoP "By requesting an exit now, you'll be exempt from penalties " &
        "stemming from not performing your validator duties, but you " &
        "won't be able to withdraw your deposited funds for the time " &
        "being. This means that your funds will be effectively frozen " &
        "until withdrawals are enabled in a future phase of Eth2."

  echoP "To understand more about the Eth2 roadmap, we recommend you " &
        "have a look at\n" &
        "https://ethereum.org/en/eth2/#roadmap"

  echoP "You must keep your validator running for at least 5 epochs " &
        "(32 minutes) after requesting a validator exit, as you will " &
        "still be required to perform validator duties until your exit " &
        "has been processed. The number of epochs could be significantly " &
        "higher depending on how many other validators are queued to exit."

  echoP "As such, we recommend you keep track of your validator's status " &
        "using an Eth2 block explorer before shutting down your beacon node."

  var choice = ""

  while not(choice == $ClientExitAction.confirmation or
            choice == $ClientExitAction.quiting) :
    echoP "To proceed to submitting your voluntary exit, please type '" &
          $ClientExitAction.confirmation &
          "' (without the quotes) in the prompt below and " &
          "press ENTER or type 'q' to quit."
    echo ""

    choice = ask "Your choice"

  if choice == $ClientExitAction.confirmation:
    ClientExitAction.confirmation
  else:
    ClientExitAction.quiting

proc getValidator*(name: string): Result[ValidatorStorage, string] =
  let ident = ValidatorIdent.decodeString(name)
  if ident.isErr():
    if not(isFile(name)):
      return err($ident.error)
    let key = importKeystoreFromFile(name)
    if key.isErr():
      return err(key.error())
    ok(ValidatorStorage(kind: ValidatorStorageKind.Keystore,
                        privateKey: key.get()))
  else:
    ok(ValidatorStorage(kind: ValidatorStorageKind.Identifier,
                        ident: ident.get()))

proc getIdent*(storage: ValidatorStorage): ValidatorIdent =
  case storage.kind
  of ValidatorStorageKind.Keystore:
    ValidatorIdent(kind: ValidatorQueryKind.Key,
                   key: storage.privateKey.toPubKey().toPubKey())
  of ValidatorStorageKind.Identifier:
    storage.ident

proc restValidatorExit(config: BeaconNodeConf) {.async.} =
  let
    client = RestClientRef.new(config.restUrlForExit).valueOr:
      raise (ref RestError)(msg: $error)

    stateIdHead = StateIdent(kind: StateQueryKind.Named,
                             value: StateIdentType.Head)
    blockIdentHead = BlockIdent(kind: BlockQueryKind.Named,
                                value: BlockIdentType.Head)
    validator = getValidator(config.exitedValidator).valueOr:
      fatal "Incorrect validator index, key or keystore path specified",
            value = config.exitedValidator, reason = error
      quit 1

  let restValidator = try:
    let response = await client.getStateValidatorPlain(stateIdHead,
                                                       validator.getIdent())
    if response.status == 200:
      let validatorInfo = decodeBytes(GetStateValidatorResponse,
                                      response.data, response.contentType)
      if validatorInfo.isErr():
        raise newException(RestError, $validatorInfo.error)
      validatorInfo.get().data
    else:
      raiseGenericError(response)
  except CatchableError as exc:
    fatal "Failed to obtain information for validator", reason = exc.msg
    quit 1

  let
    validatorIdx = restValidator.index.uint64
    validatorKey = restValidator.validator.pubkey

  let genesis = try:
    let response = await client.getGenesisPlain()
    if response.status == 200:
      let genesis = decodeBytes(GetGenesisResponse,
                                response.data,
                                response.contentType)
      if genesis.isErr():
        raise newException(RestError, $genesis.error)
      genesis.get().data
    else:
      raiseGenericError(response)
  except CatchableError as exc:
    fatal "Failed to obtain the genesis validators root of the network",
           reason = exc.msg
    quit 1

  let exitAtEpoch = if config.exitAtEpoch.isSome:
    Epoch config.exitAtEpoch.get
  else:
    let
      genesisTime =  genesis.genesis_time
      beaconClock = BeaconClock.init(genesisTime)
      time = getTime()
      slot = beaconClock.toSlot(time).slot
      epoch = slot.uint64 div 32
    Epoch epoch

  let fork = try:
    let response = await client.getStateForkPlain(stateIdHead)
    if response.status == 200:
      let fork = decodeBytes(GetStateForkResponse,
                             response.data,
                             response.contentType)
      if fork.isErr():
        raise newException(RestError, $fork.error)
      fork.get().data
    else:
      raiseGenericError(response)
  except CatchableError as exc:
    fatal "Failed to obtain the fork id of the head state",
           reason = exc.msg
    quit 1

  let
    genesis_validators_root = genesis.genesis_validators_root
    validatorKeyAsStr = "0x" & $validatorKey
    signedExit = getSignedExitMessage(config,
                                      validator,
                                      validatorKeyAsStr,
                                      exitAtEpoch,
                                      validatorIdx,
                                      fork,
                                      genesis_validators_root)

  if config.printData:
    let bytes = encodeBytes(signedExit, "application/json").valueOr:
      fatal "Unable to serialize signed exit message", reason = error
      quit 1

    echoP "You can use following command to send voluntary exit message to " &
          "remote beacon node host:\n"

    echo "curl -X 'POST' \\"
    echo "  '" & config.restUrlForExit &
         "/eth/v1/beacon/pool/voluntary_exits' \\"
    echo "  -H 'Accept: */*' \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -d '" & string.fromBytes(bytes) & "'"
    quit 0
  else:
    try:
      let choice = askForExitConfirmation()
      if choice == ClientExitAction.quiting:
        quit 0
      elif choice == ClientExitAction.confirmation:
        let
          response = await client.submitPoolVoluntaryExit(signedExit)
          success = response.status == 200
        if success:
          echo "Successfully published voluntary exit for validator " &
                $validatorIdx & "(" & validatorKeyAsStr[0..9] & ")."
          quit 0
        else:
          let responseError = try:
                Json.decode(response.data, RestErrorMessage)
          except CatchableError as exc:
            fatal "Failed to decode invalid error server response on " &
                  "`submitPoolVoluntaryExit` request", reason = exc.msg
            quit 1

          let
            responseMessage = responseError.message
            responseStacktraces = responseError.stacktraces

          echo "The voluntary exit was not submitted successfully."
          echo responseMessage & ":"
          for el in responseStacktraces.get():
            echo el
          echoP "Please try again."
          quit 1

    except CatchableError as err:
      fatal "Failed to send the signed exit message", reason = err.msg
      quit 1

proc handleValidatorExitCommand(config: BeaconNodeConf) {.async.} =
  await restValidatorExit(config)

proc doDeposits*(config: BeaconNodeConf, rng: var HmacDrbgContext) {.
    raises: [Defect, CatchableError].} =
  case config.depositsCmd
  of DepositsCmd.createTestnetDeposits:
    if config.eth2Network.isNone:
      fatal "Please specify the intended testnet for the deposits"
      quit 1
    let metadata = config.loadEth2Network()
    var seed: KeySeed
    defer: burnMem(seed)
    var walletPath: WalletPathPair

    if config.existingWalletId.isSome:
      let
        id = config.existingWalletId.get
        found = findWallet(config, id).valueOr:
          fatal "Failed to locate wallet", error = error
          quit 1

      if found.isSome:
        walletPath = found.get
      else:
        fatal "Unable to find wallet with the specified name/uuid", id
        quit 1

      var unlocked = unlockWalletInteractively(walletPath.wallet)
      if unlocked.isOk:
        swap(seed, unlocked.get)
      else:
        # The failure will be reported in `unlockWalletInteractively`.
        quit 1
    else:
      var walletRes = createWalletInteractively(rng, config)
      if walletRes.isErr:
        fatal "Unable to create wallet", err = walletRes.error
        quit 1
      else:
        swap(seed, walletRes.get.seed)
        walletPath = walletRes.get.walletPath

    if (let res = secureCreatePath(config.outValidatorsDir); res.isErr):
      fatal "Could not create directory",
        path = config.outValidatorsDir, err = ioErrorMsg(res.error)
      quit QuitFailure

    if (let res = secureCreatePath(config.outSecretsDir); res.isErr):
      fatal "Could not create directory",
        path = config.outSecretsDir, err = ioErrorMsg(res.error)
      quit QuitFailure

    let deposits = generateDeposits(
      metadata.cfg,
      rng,
      seed,
      walletPath.wallet.nextAccount,
      config.totalDeposits,
      config.outValidatorsDir,
      config.outSecretsDir,
      @[], 0, 0,
      KeystoreMode.Fast)

    if deposits.isErr:
      fatal "Failed to generate deposits", err = deposits.error
      quit 1

    try:
      let depositDataPath = if config.outDepositsFile.isSome:
        config.outDepositsFile.get.string
      else:
        config.outValidatorsDir / "deposit_data-" & $epochTime() & ".json"

      let launchPadDeposits =
        mapIt(deposits.value, LaunchPadDeposit.init(metadata.cfg, it))

      Json.saveFile(depositDataPath, launchPadDeposits)
      echo "Deposit data written to \"", depositDataPath, "\""

      walletPath.wallet.nextAccount += deposits.value.len
      let status = saveWallet(walletPath)
      if status.isErr:
        fatal "Failed to update wallet file after generating deposits",
                wallet = walletPath.path,
                error = status.error
        quit 1
    except CatchableError as err:
      fatal "Failed to create launchpad deposit data file", err = err.msg
      quit 1
  #[
  of DepositsCmd.status:
    echo "The status command is not implemented yet"
    quit 1
  ]#

  of DepositsCmd.`import`:
    let validatorKeysDir = if config.importedDepositsDir.isSome:
      config.importedDepositsDir.get
    else:
      let cwd = os.getCurrentDir()
      if dirExists(cwd / "validator_keys"):
        InputDir(cwd / "validator_keys")
      else:
        echo "The default search path for validator keys is a sub-directory " &
              "named 'validator_keys' in the current working directory. " &
              " Since no such directory exists, please either provide the " &
              "correct path as an argument or copy the imported keys in the " &
              "expected location."
        quit 1

    importKeystoresFromDir(
      rng, config.importMethod,
      validatorKeysDir.string,
      config.validatorsDir, config.secretsDir)

  of DepositsCmd.exit:
    waitFor handleValidatorExitCommand(config)
