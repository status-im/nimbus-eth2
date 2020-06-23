import
  os, strutils, terminal,
  chronicles, chronos, blscurve, nimcrypto, json_serialization, serialization,
  web3, stint, eth/keys, confutils,
  spec/[datatypes, digest, crypto, keystore], conf, ssz/merkleization, merkle_minimal

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

proc generateDeposits*(totalValidators: int,
                       validatorsDir: string,
                       secretsDir: string): Result[seq[Deposit], GenerateDepositsError] =
  var deposits: seq[Deposit]

  info "Generating deposits", totalValidators, validatorsDir, secretsDir
  for i in 0 ..< totalValidators:
    let password = KeyStorePass getRandomBytesOrPanic(32).toHex
    let credentials = generateCredentials(password = password)

    let
      keyName = intToStr(i, 6) & "_" & $(credentials.signingKey.toPubKey)
      validatorDir = validatorsDir / keyName
      passphraseFile = secretsDir / keyName
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

    deposits.add credentials.prepareDeposit()

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

{.pop.}

proc sendDeposits*(deposits: seq[Deposit],
                   web3Url, depositContractAddress, privateKey: string,
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

  let contractAddress = Address.fromHex(depositContractAddress)
  let depositContract = web3.contractSender(DepositContract, contractAddress)

  for i, dp in deposits:
    let status = await depositContract.deposit(
      Bytes48(dp.data.pubKey.toRaw()),
      Bytes32(dp.data.withdrawal_credentials.data),
      Bytes96(dp.data.signature.toRaw()),
      FixedBytes[32](hash_tree_root(dp.data).data)).send(value = 32.u256.ethToWei, gasPrice = 1)

    info "Deposit sent", status = $status

    if delayGenerator != nil:
      await sleepAsync(delayGenerator())

