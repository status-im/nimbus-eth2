import
  std/[os, strutils, terminal, wordwrap],
  stew/byteutils, chronicles, chronos, web3, stint, json_serialization,
  serialization, blscurve, eth/common/eth_types, eth/keys, confutils, bearssl,
  spec/[datatypes, digest, crypto, keystore],
  conf, ssz/merkleization, merkle_minimal, network_metadata

export
  keystore

contract(DepositContract):
  proc deposit(pubkey: Bytes48, withdrawalCredentials: Bytes32, signature: Bytes96, deposit_data_root: FixedBytes[32])

const
  keystoreFileName* = "keystore.json"
  depositFileName* = "deposit.json"

type
  DelayGenerator* = proc(): chronos.Duration {.closure, gcsafe.}

{.push raises: [Defect].}

proc ethToWei(eth: UInt256): UInt256 =
  eth * 1000000000000000000.u256

proc loadKeyStore(conf: BeaconNodeConf|ValidatorClientConf,
                  validatorsDir, keyName: string): Option[ValidatorPrivKey] =
  let
    keystorePath = validatorsDir / keyName / keystoreFileName
    keystoreContents = KeyStoreContent:
      try: readFile(keystorePath)
      except IOError as err:
        error "Failed to read keystore", err = err.msg, path = keystorePath
        return

  let passphrasePath = conf.secretsDir / keyName
  if fileExists(passphrasePath):
    let
      passphrase = KeyStorePass:
        try: readFile(passphrasePath)
        except IOError as err:
          error "Failed to read passphrase file", err = err.msg, path = passphrasePath
          return

    let res = decryptKeystore(keystoreContents, passphrase)
    if res.isOk:
      return res.get.some
    else:
      error "Failed to decrypt keystore", keystorePath, passphrasePath
      return

  if conf.nonInteractive:
    error "Unable to load validator key store. Please ensure matching passphrase exists in the secrets dir",
      keyName, validatorsDir, secretsDir = conf.secretsDir
    return

  var remainingAttempts = 3
  var prompt = "Please enter passphrase for key \"" & validatorsDir/keyName & "\"\n"
  while remainingAttempts > 0:
    let passphrase = KeyStorePass:
      try: readPasswordFromStdin(prompt)
      except IOError:
        error "STDIN not readable. Cannot obtain KeyStore password"
        return

    let decrypted = decryptKeystore(keystoreContents, passphrase)
    if decrypted.isOk:
      return decrypted.get.some
    else:
      prompt = "Keystore decryption failed. Please try again"
      dec remainingAttempts

iterator validatorKeys*(conf: BeaconNodeConf|ValidatorClientConf): ValidatorPrivKey =
  for validatorKeyFile in conf.validators:
    try:
      yield validatorKeyFile.load
    except CatchableError as err:
      error "Failed to load validator private key",
            file = validatorKeyFile.string, err = err.msg
      quit 1

  let validatorsDir = conf.validatorsDir
  try:
    for kind, file in walkDir(validatorsDir):
      if kind == pcDir:
        let keyName = splitFile(file).name
        let key = loadKeyStore(conf, validatorsDir, keyName)
        if key.isSome:
          yield key.get
        else:
          quit 1
  except OSError as err:
    error "Validator keystores directory not accessible",
          path = validatorsDir, err = err.msg
    quit 1

type
  GenerateDepositsError = enum
    RandomSourceDepleted,
    FailedToCreateValidatoDir
    FailedToCreateSecretFile
    FailedToCreateKeystoreFile
    FailedToCreateDepositFile

proc generateDeposits*(preset: RuntimePreset,
                       rng: var BrHmacDrbgContext,
                       totalValidators: int,
                       validatorsDir: string,
                       secretsDir: string): Result[seq[Deposit], GenerateDepositsError] =
  var deposits: seq[Deposit]

  info "Generating deposits", totalValidators, validatorsDir, secretsDir
  for i in 0 ..< totalValidators:
    let password = KeyStorePass getRandomBytes(rng, 32).toHex
    let credentials = generateCredentials(rng, password = password)

    let
      keyName = intToStr(i, 6) & "_" & $(credentials.signingKey.toPubKey)
      validatorDir = validatorsDir / keyName
      depositFile = validatorDir / depositFileName
      keystoreFile = validatorDir / keystoreFileName

    if existsDir(validatorDir) and existsFile(depositFile):
      continue

    try: createDir validatorDir
    except OSError, IOError: return err FailedToCreateValidatoDir

    try: writeFile(secretsDir / keyName, password.string)
    except IOError: return err FailedToCreateSecretFile

    try: writeFile(keystoreFile, credentials.keyStore.string)
    except IOError: return err FailedToCreateKeystoreFile

    deposits.add credentials.prepareDeposit(preset)

    # Does quadratic additional work, but fast enough, and otherwise more
    # cleanly allows free intermixing of pre-existing and newly generated
    # deposit and private key files. TODO: only generate new Merkle proof
    # for the most recent deposit if this becomes bottleneck.
    attachMerkleProofs(deposits)
    try: Json.saveFile(depositFile, deposits[^1], pretty = true)
    except: return err FailedToCreateDepositFile

  ok deposits

proc loadDeposits*(depositsDir: string): seq[Deposit] =
  try:
    for kind, dir in walkDir(depositsDir):
      if kind == pcDir:
        let depositFile = dir / depositFileName
        try:
          result.add Json.loadFile(depositFile, Deposit)
        except IOError as err:
          error "Failed to open deposit file", depositFile, err = err.msg
          quit 1
        except SerializationError as err:
          error "Invalid deposit file", error = formatMsg(err, depositFile)
          quit 1
  except OSError as err:
    error "Deposits directory not accessible",
           path = depositsDir, err = err.msg
    quit 1

const
  minPasswordLen = 10

  mostCommonPasswords = wordListArray(
    currentSourcePath.parentDir /
      "../vendor/nimbus-security-resources/passwords/10-million-password-list-top-100000.txt",
    minWordLength = minPasswordLen)

proc createWalletInteractively*(
    rng: var BrHmacDrbgContext,
    conf: BeaconNodeConf): Result[OutFile, cstring] =

  if conf.nonInteractive:
    return err "Wallets can be created only in interactive mode"

  var mnemonic = generateMnemonic(rng)
  defer: burnMem(mnemonic)

  template ask(prompt: string): string =
    try:
      stdout.write prompt, ": "
      stdin.readLine()
    except IOError:
      return err "Failed to read data from stdin"

  template echo80(msg: string) =
    echo wrapWords(msg, 80)

  proc readPasswordInput(prompt: string, password: var TaintedString): bool =
    try: readPasswordFromStdin(prompt, password)
    except IOError: false

  echo80 "The generated wallet is uniquely identified by a seed phrase " &
         "consisting of 24 words. In case you lose your wallet and you " &
         "need to restore it on a different machine, you must use the " &
         "words displayed below:"

  try:
    echo ""
    stdout.setStyle({styleBright})
    stdout.setForegroundColor fgCyan
    echo80 $mnemonic
    stdout.resetAttributes()
    echo ""
  except IOError, ValueError:
    return err "Failed to write to the standard output"

  echo80 "Please back up the seed phrase now to a safe location as " &
         "if you are protecting a sensitive password. The seed phrase " &
         "can be used to withdrawl funds from your wallet."

  echo ""
  echo "Did you back up your seed recovery phrase?\p" &
       "(please type 'yes' to continue or press enter to quit)"

  while true:
    let answer = ask "Answer"
    if answer == "":
      return err "Wallet creation aborted"
    elif answer != "yes":
      echo "To continue, please type 'yes' (without the quotes) or press enter to quit"
    else:
      break

  echo ""
  echo80 "When you perform operations with your wallet such as withdrawals " &
         "and additional deposits, you'll be asked to enter a password. " &
         "Please note that this password is local to the current Nimbus " &
         "installation and can be changed at any time."
  echo ""

  while true:
    var password, confirmedPassword: TaintedString
    try:
      var firstTry = true

      template prompt: string =
        if firstTry:
          "Please enter a password:"
        else:
          "Please enter a new password:"

      while true:
        if not readPasswordInput(prompt, password):
          return err "Failed to read a password from stdin"

        if password.len < minPasswordLen:
          try:
            echo "The entered password should be at least $1 characters." %
                 [$minPasswordLen]
          except ValueError as err:
            raiseAssert "The format string above is correct"
        elif password in mostCommonPasswords:
          echo80 "The entered password is too commonly used and it would be easy " &
                 "to brute-force with automated tools."
        else:
          break

        firstTry = false

      if not readPasswordInput("Please repeat the password:", confirmedPassword):
        return err "Failed to read a password from stdin"

      if password != confirmedPassword:
        echo "Passwords don't match, please try again"
        continue

      var name: WalletName
      if conf.createdWalletName.isSome:
        name = conf.createdWalletName.get
      else:
        echo ""
        echo80 "For your convenience, the wallet can be identified with a name " &
               "of your choice. Please enter a wallet name below or press ENTER " &
               "to continue with a machine-generated name."

        while true:
          var enteredName = ask "Wallet name"
          if enteredName.len > 0:
            name = try: WalletName.parseCmdArg(enteredName)
                   except CatchableError as err:
                     echo err.msg & ". Please try again."
                     continue
          break

      let (uuid, walletContent) = KdfPbkdf2.createWalletContent(
                                    rng, mnemonic,
                                    name = name,
                                    password = KeyStorePass password)
      try:
        var outWalletFile: OutFile

        if conf.createdWalletFile.isSome:
          outWalletFile = conf.createdWalletFile.get
          createDir splitFile(string outWalletFile).dir
        else:
          let walletsDir = conf.walletsDir
          createDir walletsDir
          outWalletFile = OutFile(walletsDir / addFileExt(string uuid, "json"))

        writeFile(string outWalletFile, string walletContent)
        echo "Wallet file written to ", outWalletFile
        return ok outWalletFile
      except CatchableError as err:
        return err "Failed to write wallet file"

    finally:
      burnMem(password)
      burnMem(confirmedPassword)

{.pop.}

# TODO: async functions should note take `seq` inputs because
#       this leads to full copies.
proc sendDeposits*(deposits: seq[Deposit],
                   web3Url, privateKey: string,
                   depositContractAddress: Eth1Address,
                   delayGenerator: DelayGenerator = nil) {.async.} =
  var web3 = await newWeb3(web3Url)
  if privateKey.len != 0:
    web3.privateKey = some(PrivateKey.fromHex(privateKey).tryGet)
  else:
    let accounts = await web3.provider.eth_accounts()
    if accounts.len == 0:
      error "No account offered by the web3 provider", web3Url
      return
    web3.defaultAccount = accounts[0]

  let depositContract = web3.contractSender(DepositContract,
                                            Address depositContractAddress)
  for i, dp in deposits:
    let status = await depositContract.deposit(
      Bytes48(dp.data.pubKey.toRaw()),
      Bytes32(dp.data.withdrawal_credentials.data),
      Bytes96(dp.data.signature.toRaw()),
      FixedBytes[32](hash_tree_root(dp.data).data)).send(value = 32.u256.ethToWei, gasPrice = 1)

    info "Deposit sent", status = $status

    if delayGenerator != nil:
      await sleepAsync(delayGenerator())

proc sendDeposits*(config: BeaconNodeConf,
                   deposits: seq[Deposit],
                   delayGenerator: DelayGenerator = nil) {.async.} =
  info "Sending deposits",
    web3 = config.web3Url,
    depositContract = config.depositContractAddress

  await sendDeposits(
    deposits,
    config.web3Url,
    config.depositPrivateKey,
    config.depositContractAddress.get,
    delayGenerator)

