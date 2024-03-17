{.push raises: [].}

import
  std/[os, unicode],
  chronicles, chronos, json_serialization,
  bearssl/rand,
  serialization, blscurve, eth/common/eth_types, confutils,
  ".."/spec/[eth2_merkleization, keystore, crypto],
  ".."/spec/datatypes/base,
  stew/io2, libp2p/crypto/crypto as lcrypto,
  nimcrypto/utils as ncrutils,
  ".."/[conf, filepath, beacon_clock],
  ".."/networking/network_metadata,
  ./validator_pool

from std/terminal import
  ForegroundColor, Style, readPasswordFromStdin, getch, resetAttributes,
  setForegroundColor, setStyle

export
  keystore, validator_pool, crypto, rand, Web3SignerUrl

{.localPassC: "-fno-lto".} # no LTO for crypto

const
  KeystoreFileName = "keystore.json"
  KeyNameSize = 98 # 0x + hexadecimal key representation 96 characters.
  MaxKeystoreFileSize = 65536

func init*(T: type KeystoreData,
           privateKey: ValidatorPrivKey,
           keystore: Keystore, handle: FileLockHandle): T {.raises: [].} =
  KeystoreData(
    privateKey: privateKey,
    description: keystore.description,
    path: keystore.path,
    uuid: keystore.uuid,
    handle: handle,
    version: uint64(keystore.version),
    pubkey: privateKey.toPubKey().toPubKey()
  )

proc checkSensitiveFilePermissions(filePath: string): bool =
  ## Check if ``filePath`` has only "(600) rw-------" permissions.
  ## Procedure returns ``false`` if permissions are different and we can't
  ## correct them.
  when defined(windows):
    let cres = checkCurrentUserOnlyACL(filePath)
    if cres.isErr():
      fatal "Could not check file's ACL",
             key_path = filePath, errorCode = $cres.error,
             errorMsg = ioErrorMsg(cres.error)
      return false
    else:
      if cres.get() == false:
        fatal "File has insecure permissions", key_path = filePath
        return false
  else:
    let requiredPerms = 0o600
    let currPermsRes = getPermissions(filePath)
    if currPermsRes.isErr():
      error "Could not check file permissions",
            key_path = filePath, errorCode = $currPermsRes.error,
            errorMsg = ioErrorMsg(currPermsRes.error)
      return false
    else:
      let currPerms = currPermsRes.get()
      if currPerms != requiredPerms:
        warn "File has insecure permissions. Correcting them.",
              key_path = filePath
        let newPermsRes = setPermissions(filePath, requiredPerms)
        if newPermsRes.isErr():
          fatal "Could not set data directory permissions",
                 key_path = filePath,
                 errorCode = $newPermsRes.error,
                 errorMsg = ioErrorMsg(newPermsRes.error)
          return false

  return true

proc keyboardGetPassword[T](prompt: string, attempts: int,
                            pred: proc(p: string): KsResult[T] {.
     gcsafe, raises: [].}): KsResult[T] =
  var
    remainingAttempts = attempts
    counter = 1

  while remainingAttempts > 0:
    let passphrase =
      try:
        readPasswordFromStdin(prompt)
      except IOError:
        error "Could not read password from stdin"
        return
    os.sleep(1000 * counter)
    let res = pred(passphrase)
    if res.isOk():
      return res
    else:
      inc(counter)
      dec(remainingAttempts)
  err("Failed to decrypt keystore")

proc loadSecretFile(path: string): KsResult[KeystorePass] {.
     raises: [].} =
  let res = readAllChars(path)
  if res.isErr():
    return err(ioErrorMsg(res.error()))
  ok(KeystorePass.init(res.get()))

proc loadLocalKeystoreImpl(validatorsDir, secretsDir, keyName: string,
                           nonInteractive: bool,
                           cache: KeystoreCacheRef): Opt[KeystoreData] =
  let
    keystorePath = validatorsDir / keyName / KeystoreFileName
    passphrasePath = secretsDir / keyName
    handle =
      block:
        let res = openLockedFile(keystorePath)
        if res.isErr():
          error "Unable to lock keystore file", key_path = keystorePath,
                error_msg = ioErrorMsg(res.error())
          return Opt.none(KeystoreData)
        res.get()

  var success = false
  defer:
    if not(success):
      discard handle.closeLockedFile()

  let
    keystore =
      block:
        let gres = handle.getData(MaxKeystoreFileSize)
        if gres.isErr():
          error "Could not read local keystore file", key_path = keystorePath,
                error_msg = ioErrorMsg(gres.error())
          return Opt.none(KeystoreData)
        let buffer = gres.get()
        let data =
          try:
            parseKeystore(buffer)
          except SerializationError as e:
            error "Invalid local keystore file", key_path = keystorePath,
                  error_msg = e.formatMsg(keystorePath)
            return Opt.none(KeystoreData)
        data

  if fileExists(passphrasePath):
    if not(checkSensitiveFilePermissions(passphrasePath)):
      error "Password file has insecure permissions", key_path = keystorePath
      return Opt.none(KeystoreData)

    let passphrase =
      block:
        let res = loadSecretFile(passphrasePath)
        if res.isErr():
          error "Failed to read passphrase file", error_msg = res.error(),
                path = passphrasePath
          return Opt.none(KeystoreData)
        res.get()

    let res = decryptKeystore(keystore, passphrase, cache)
    if res.isOk():
      success = true
      return Opt.some(KeystoreData.init(res.get(), keystore, handle))
    else:
      error "Failed to decrypt keystore", key_path = keystorePath,
            secure_path = passphrasePath
      return Opt.none(KeystoreData)

  if nonInteractive:
    error "Unable to load validator key store. Please ensure matching " &
          "passphrase exists in the secrets dir", key_path = keystorePath,
          key_name = keyName, validatorsDir, secretsDir = secretsDir
    return Opt.none(KeystoreData)

  let prompt = "Please enter passphrase for key \"" &
               (validatorsDir / keyName) & "\": "
  let res = keyboardGetPassword[ValidatorPrivKey](prompt, 3,
    proc (password: string): KsResult[ValidatorPrivKey] =
      let decrypted = decryptKeystore(keystore, KeystorePass.init password,
                                      cache)
      if decrypted.isErr():
        error "Keystore decryption failed. Please try again",
              keystore_path = keystorePath
      decrypted
  )

  if res.isErr():
    return Opt.none(KeystoreData)

  success = true
  Opt.some(KeystoreData.init(res.get(), keystore, handle))

proc loadKeystore(validatorsDir, secretsDir, keyName: string,
                   nonInteractive: bool,
                   cache: KeystoreCacheRef): Opt[KeystoreData] =
  let
    keystorePath = validatorsDir / keyName
    localKeystorePath = keystorePath / KeystoreFileName

  if fileExists(localKeystorePath):
    loadLocalKeystoreImpl(validatorsDir, secretsDir, keyName, nonInteractive,
                          cache)
  else:
    error "Unable to find any keystore files", keystorePath
    Opt.none(KeystoreData)

func fsName(pubkey: ValidatorPubKey|CookedPubKey): string =
  "0x" & pubkey.toHex()

func checkKeyName(keyName: string): Result[void, string] =
  const keyAlphabet = {'a'..'f', 'A'..'F', '0'..'9'}
  if len(keyName) != KeyNameSize:
    return err("Length should be at least " & $KeyNameSize & " characters")
  if keyName[0] != '0' or keyName[1] != 'x':
    return err("Name should be prefixed with '0x' characters")
  for index in 2 ..< len(keyName):
    if keyName[index] notin keyAlphabet:
      return err("Incorrect characters found in name")
  ok()

proc existsKeystore(keystoreDir: string): bool {.
     raises: [].} =
  fileExists(keystoreDir / KeystoreFileName)

iterator listLoadableKeystores*(validatorsDir, secretsDir: string,
                                nonInteractive: bool,
                                cache: KeystoreCacheRef): KeystoreData =
  const IncorrectName = "Incorrect keystore directory name, ignoring"
  try:
    for kind, file in walkDir(validatorsDir):
      if kind == pcDir:
        let
          keyName = splitFile(file).name
          keystoreDir = validatorsDir / keyName
          nameres = checkKeyName(keyName)

        if nameres.isErr():
          notice IncorrectName, reason = nameres.error
          continue

        if not(existsKeystore(keystoreDir)):
          notice "Incorrect keystore directory, ignoring",
                 reason = "Missing keystore files ('keystore.json' or " &
                          "'remote_keystore.json')"
          continue

        let
          keystore = loadKeystore(validatorsDir, secretsDir, keyName,
                                  nonInteractive, cache).valueOr:
            fatal "Unable to load keystore", keystore = file
            quit 1

        yield keystore

  except OSError as err:
    error "Validator keystores directory is not accessible",
          path = validatorsDir, err = err.msg
    quit 1

iterator listLoadableKeystores*(config: AnyConf,
                                cache: KeystoreCacheRef): KeystoreData =
  for el in listLoadableKeystores(config.validatorsDir(),
                                  config.secretsDir(),
                                  config.nonInteractive,
                                  cache):
    yield el

type
  KeystoreGenerationErrorKind = enum
    FailedToCreateValidatorsDir
    FailedToCreateKeystoreDir
    FailedToCreateSecretsDir
    FailedToCreateSecretFile
    FailedToCreateKeystoreFile
    DuplicateKeystoreDir
    DuplicateKeystoreFile

  KeystoreGenerationError = object
    case kind: KeystoreGenerationErrorKind
    of FailedToCreateKeystoreDir,
       FailedToCreateValidatorsDir,
       FailedToCreateSecretsDir,
       FailedToCreateSecretFile,
       FailedToCreateKeystoreFile,
       DuplicateKeystoreDir,
       DuplicateKeystoreFile:
      error: string

func mapErrTo[T, E](r: Result[T, E], v: static KeystoreGenerationErrorKind):
    Result[T, KeystoreGenerationError] =
  r.mapErr(proc (e: E): KeystoreGenerationError =
    KeystoreGenerationError(kind: v, error: $e))

proc createLocalValidatorFiles(
       secretsDir, validatorsDir, keystoreDir,
       secretFile, passwordAsString, keystoreFile,
       encodedStorage: string
     ): Result[void, KeystoreGenerationError] {.raises: [].} =

  var success = false # becomes true when everything is created successfully

  # secretsDir:
  let secretsDirExisted: bool = dirExists(secretsDir)
  if not(secretsDirExisted):
    ? secureCreatePath(secretsDir).mapErrTo(FailedToCreateSecretsDir)
  defer:
    if not (success or secretsDirExisted):
      discard io2.removeDir(secretsDir)

  # validatorsDir:
  let validatorsDirExisted: bool = dirExists(validatorsDir)
  if not(validatorsDirExisted):
    ? secureCreatePath(validatorsDir).mapErrTo(FailedToCreateValidatorsDir)
  defer:
    if not (success or validatorsDirExisted):
      discard io2.removeDir(validatorsDir)

  # keystoreDir:
  ? secureCreatePath(keystoreDir).mapErrTo(FailedToCreateKeystoreDir)
  defer:
    if not success:
      discard io2.removeDir(keystoreDir)

  # secretFile:
  ? secureWriteFile(secretFile,
                    passwordAsString).mapErrTo(FailedToCreateSecretFile)
  defer:
    if not success:
      discard io2.removeFile(secretFile)

  # keystoreFile:
  ? secureWriteFile(keystoreFile,
                    encodedStorage).mapErrTo(FailedToCreateKeystoreFile)

  success = true
  ok()

proc saveKeystore(
       rng: var HmacDrbgContext,
       validatorsDir, secretsDir: string,
       signingKey: ValidatorPrivKey,
       signingPubKey: CookedPubKey,
       signingKeyPath: KeyPath,
       password: string,
       salt: openArray[byte] = @[],
       mode = Secure
     ): Result[void, KeystoreGenerationError] {.raises: [].} =
  let
    keypass = KeystorePass.init(password)
    keyName = signingPubKey.fsName
    keystoreDir = validatorsDir / keyName
    keystoreFile = keystoreDir / KeystoreFileName

  if dirExists(keystoreDir):
    return err(KeystoreGenerationError(kind: DuplicateKeystoreDir,
      error: "Keystore directory already exists"))
  if fileExists(keystoreFile):
    return err(KeystoreGenerationError(kind: DuplicateKeystoreFile,
      error: "Keystore file already exists"))

  let keyStore = createKeystore(kdfPbkdf2, rng, signingKey,
                                keypass, signingKeyPath,
                                mode = mode, salt = salt)
  let encodedStorage = Json.encode(keyStore)

  ? createLocalValidatorFiles(secretsDir, validatorsDir,
                              keystoreDir,
                              secretsDir / keyName, keypass.str,
                              keystoreFile, encodedStorage)
  ok()

from ".."/spec/beaconstate import has_eth1_withdrawal_credential

proc generateDeposits*(cfg: RuntimeConfig,
                       rng: var HmacDrbgContext,
                       seed: KeySeed,
                       firstValidatorIdx, totalNewValidators: int,
                       validatorsDir: string,
                       secretsDir: string,
                       mode = Secure): Result[seq[DepositData],
                                              KeystoreGenerationError] =
  var deposits: seq[DepositData]

  notice "Generating deposits", totalNewValidators, validatorsDir, secretsDir

  # We'll reuse a single variable here to make the secret
  # scrubbing (burnMem) easier to handle:
  var baseKey = deriveMasterKey(seed)
  defer: burnMem(baseKey)
  baseKey = deriveChildKey(baseKey, baseKeyPath)

  var
    salt = rng.generateKeystoreSalt()
    password = KeystorePass.init ncrutils.toHex(rng.generateBytes(32))

  defer:
    burnMem(salt)
    burnMem(password)

  let localValidatorsCount = totalNewValidators
  for i in 0 ..< localValidatorsCount:
    let validatorIdx = firstValidatorIdx + i

    # We'll reuse a single variable here to make the secret
    # scrubbing (burnMem) easier to handle:
    var derivedKey = baseKey
    defer: burnMem(derivedKey)
    derivedKey = deriveChildKey(derivedKey, validatorIdx)
    derivedKey = deriveChildKey(derivedKey, 0) # This is witdrawal key
    let withdrawalPubKey = derivedKey.toPubKey
    derivedKey = deriveChildKey(derivedKey, 0) # This is the signing key
    let signingPubKey = derivedKey.toPubKey

    ? saveKeystore(rng, validatorsDir, secretsDir,
                   derivedKey, signingPubKey,
                   makeKeyPath(validatorIdx, signingKeyKind), password.str,
                   salt, mode)

    deposits.add prepareDeposit(
      cfg, withdrawalPubKey, derivedKey, signingPubKey)

  ok deposits

type
  # This is not particularly well-standardized yet.
  # Some relevant code for generating (1) and validating (2) the data can be found below:
  # 1) https://github.com/ethereum/eth2.0-deposit-cli/blob/dev/eth2deposit/credentials.py
  # 2) https://github.com/ethereum/eth2.0-deposit/blob/dev/src/pages/UploadValidator/validateDepositKey.ts
  LaunchPadDeposit* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei
    signature*: ValidatorSig
    deposit_message_root*: Eth2Digest
    deposit_data_root*: Eth2Digest
    fork_version*: Version

func init*(T: type LaunchPadDeposit,
           cfg: RuntimeConfig, d: DepositData): T =
  T(pubkey: d.pubkey,
    withdrawal_credentials: d.withdrawal_credentials,
    amount: d.amount,
    signature: d.signature,
    deposit_message_root: hash_tree_root(d as DepositMessage),
    deposit_data_root: hash_tree_root(d),
    fork_version: cfg.GENESIS_FORK_VERSION)

func `as`*(copied: LaunchPadDeposit, T: type DepositData): T =
  T(pubkey: copied.pubkey,
    withdrawal_credentials: copied.withdrawal_credentials,
    amount: copied.amount,
    signature: copied.signature)
