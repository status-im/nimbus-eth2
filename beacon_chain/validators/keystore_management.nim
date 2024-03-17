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
from std/wordwrap import wrapWords
from zxcvbn import passwordEntropy

export
  keystore, validator_pool, crypto, rand, Web3SignerUrl

when defined(windows):
  import stew/[windows/acl]

{.localPassC: "-fno-lto".} # no LTO for crypto

const
  KeystoreFileName = "keystore.json"
  RemoteKeystoreFileName = "remote_keystore.json"
  FeeRecipientFilename = "suggested_fee_recipient.hex"
  GasLimitFilename = "suggested_gas_limit.json"
  BuilderConfigPath = "payload_builder.json"
  KeyNameSize = 98 # 0x + hexadecimal key representation 96 characters.
  MaxKeystoreFileSize = 65536

type
  WalletPathPair = object
    wallet: Wallet
    path: string

  CreatedWallet = object
    walletPath: WalletPathPair
    seed: KeySeed

  KmResult[T] = Result[T, cstring]

  RemoveValidatorStatus {.pure.} = enum
    deleted = "Deleted"
    notFound = "Not found"

  AddValidatorStatus {.pure.} = enum
    existingArtifacts = "Keystore artifacts already exists"
    failed = "Validator not added"

  AddValidatorFailure = object
    status: AddValidatorStatus
    message: string

  ImportResult[T] = Result[T, AddValidatorFailure]

  ValidatorPubKeyToDataFn =
    proc (pubkey: ValidatorPubKey): Opt[ValidatorAndIndex]
         {.raises: [], gcsafe.}

  GetCapellaForkVersionFn =
    proc (): Opt[Version] {.raises: [], gcsafe.}
  GetDenebForkEpochFn =
    proc (): Opt[Epoch] {.raises: [], gcsafe.}
  GetForkFn =
    proc (epoch: Epoch): Opt[Fork] {.raises: [], gcsafe.}
  GetGenesisFn =
    proc (): Eth2Digest {.raises: [], gcsafe.}

  KeymanagerHost = object
    validatorPool: ref ValidatorPool
    keystoreCache: KeystoreCacheRef
    rng: ref HmacDrbgContext
    keymanagerToken: string
    validatorsDir: string
    secretsDir: string
    defaultFeeRecipient: Opt[Eth1Address]
    defaultGasLimit: uint64
    defaultBuilderAddress: Opt[string]
    getValidatorAndIdxFn: ValidatorPubKeyToDataFn
    getBeaconTimeFn: GetBeaconTimeFn
    getCapellaForkVersionFn: GetCapellaForkVersionFn
    getDenebForkEpochFn: GetDenebForkEpochFn
    getForkFn: GetForkFn
    getGenesisFn: GetGenesisFn

  MultipleKeystoresDecryptor = object
    previouslyUsedPassword: string

  QueryResult = Result[seq[KeystoreData], string]

const
  minPasswordLen = 12
  minPasswordEntropy = 60.0

func dispose(decryptor: var MultipleKeystoresDecryptor) =
  burnMem(decryptor.previouslyUsedPassword)

func init(T: type KeymanagerHost,
           validatorPool: ref ValidatorPool,
           keystoreCache: KeystoreCacheRef,
           rng: ref HmacDrbgContext,
           keymanagerToken: string,
           validatorsDir: string,
           secretsDir: string,
           defaultFeeRecipient: Opt[Eth1Address],
           defaultGasLimit: uint64,
           defaultBuilderAddress: Opt[string],
           getValidatorAndIdxFn: ValidatorPubKeyToDataFn,
           getBeaconTimeFn: GetBeaconTimeFn,
           getCapellaForkVersionFn: GetCapellaForkVersionFn,
           getDenebForkEpochFn: GetDenebForkEpochFn,
           getForkFn: GetForkFn,
           getGenesisFn: GetGenesisFn): T =
  T(validatorPool: validatorPool,
    keystoreCache: keystoreCache,
    rng: rng,
    keymanagerToken: keymanagerToken,
    validatorsDir: validatorsDir,
    secretsDir: secretsDir,
    defaultFeeRecipient: defaultFeeRecipient,
    defaultGasLimit: defaultGasLimit,
    defaultBuilderAddress: defaultBuilderAddress,
    getValidatorAndIdxFn: getValidatorAndIdxFn,
    getBeaconTimeFn: getBeaconTimeFn,
    getCapellaForkVersionFn: getCapellaForkVersionFn,
    getDenebForkEpochFn: getDenebForkEpochFn,
    getForkFn: getForkFn,
    getGenesisFn: getGenesisFn)

proc echoP(msg: string) =
  ## Prints a paragraph aligned to 80 columns
  echo ""
  echo wrapWords(msg, 80)

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

func init(T: type AddValidatorFailure, status: AddValidatorStatus,
          msg = ""): AddValidatorFailure {.raises: [].} =
  AddValidatorFailure(status: status, message: msg)

proc checkAndCreateDataDir(dataDir: string): bool =
  when defined(posix):
    let requiredPerms = 0o700
    if isDir(dataDir):
      let currPermsRes = getPermissions(dataDir)
      if currPermsRes.isErr():
        fatal "Could not check data directory permissions",
               data_dir = dataDir, errorCode = $currPermsRes.error,
               errorMsg = ioErrorMsg(currPermsRes.error)
        return false
      else:
        let currPerms = currPermsRes.get()
        if currPerms != requiredPerms:
          warn "Data directory has insecure permissions. Correcting them.",
                data_dir = dataDir
          let newPermsRes = setPermissions(dataDir, requiredPerms)
          if newPermsRes.isErr():
            fatal "Could not set data directory permissions",
                   data_dir = dataDir,
                   errorCode = $newPermsRes.error,
                   errorMsg = ioErrorMsg(newPermsRes.error)
            return false
    else:
      if (let res = secureCreatePath(dataDir); res.isErr):
        fatal "Could not create data directory",
          path = dataDir, err = ioErrorMsg(res.error), errorCode = $res.error
        return false
  elif defined(windows):
    let amask = {AccessFlags.Read, AccessFlags.Write, AccessFlags.Execute}
    if fileAccessible(dataDir, amask):
      let cres = checkCurrentUserOnlyACL(dataDir)
      if cres.isErr():
        fatal "Could not check data folder's ACL",
               path = dataDir, errorCode = $cres.error,
               errorMsg = ioErrorMsg(cres.error)
        return false
      else:
        if cres.get() == false:
          fatal "Data folder has insecure ACL", path = dataDir
          return false
    else:
      if (let res = secureCreatePath(dataDir); res.isErr):
        fatal "Could not create data folder",
          path = dataDir, err = ioErrorMsg(res.error), errorCode = $res.error
        return false
  else:
    fatal "Unsupported operation system"
    return false

  return true

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

proc keyboardCreatePassword(prompt: string,
                            confirm: string,
                            allowEmpty = false): KsResult[string] =
  while true:
    let password =
      try:
        readPasswordFromStdin(prompt)
      except IOError:
        error "Could not read password from stdin"
        return err("Could not read password from stdin")

    if password.len == 0 and allowEmpty:
      return ok("")

    # We treat `password` as UTF-8 encoded string.
    if validateUtf8(password) == -1:
      if runeLen(password) < minPasswordLen:
        echoP "The entered password should be at least " & $minPasswordLen &
              " characters."
        echo ""
        continue
      elif passwordEntropy(password) < minPasswordEntropy:
        echoP "The entered password has low entropy and may be easy to " &
              "brute-force with automated tools. Please increase the " &
              "variety of the user characters."
        continue
    else:
      echoP "Entered password is not valid UTF-8 string"
      echo ""
      continue

    let confirmedPassword =
      try:
        readPasswordFromStdin(confirm)
      except IOError:
        error "Could not read password from stdin"
        return err("Could not read password from stdin")

    if password != confirmedPassword:
      echo "Passwords don't match, please try again\n"
      continue

    return ok(password)

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
    remoteKeystorePath = keystorePath / RemoteKeystoreFileName

  if fileExists(localKeystorePath):
    loadLocalKeystoreImpl(validatorsDir, secretsDir, keyName, nonInteractive,
                          cache)
  else:
    error "Unable to find any keystore files", keystorePath
    Opt.none(KeystoreData)

proc removeValidatorFiles(validatorsDir, secretsDir, keyName: string,
                          ): KmResult[RemoveValidatorStatus] {.
     raises: [].} =
  let
    keystoreDir = validatorsDir / keyName
    keystoreFile = keystoreDir / KeystoreFileName
    secretFile = secretsDir / keyName

  if not(dirExists(keystoreDir)):
    return ok(RemoveValidatorStatus.notFound)

  if not(fileExists(keystoreFile)):
    return ok(RemoveValidatorStatus.notFound)

  block:
    let res = io2.removeFile(keystoreFile)
    if res.isErr():
      return err("Could not remove keystore file")
  block:
    let res = io2.removeFile(secretFile)
    if res.isErr() and fileExists(secretFile):
      return err("Could not remove password file")
  # We remove folder with all subfolders and files inside.
  try:
    removeDir(keystoreDir, false)
  except OSError:
    return err("Could not remove keystore directory")

  ok(RemoveValidatorStatus.deleted)

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

proc queryValidatorsSource(web3signerUrl: Web3SignerUrl):
    Future[QueryResult] {.async: (raises: [CancelledError]).} =
  return QueryResult.err("")

iterator listLoadableKeys(validatorsDir, secretsDir: string): CookedPubKey =
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

        let kres = ValidatorPubKey.fromHex(keyName)
        if kres.isErr():
          let reason = "Directory name should be correct validators public key"
          notice IncorrectName, reason = reason
          continue

        let publicKey = kres.get()

        let cres = publicKey.load().valueOr:
          let reason = "Directory name should be correct validators public " &
                       "key (point is not in curve)"
          notice IncorrectName, reason = reason
          continue

        yield cres

  except OSError as err:
    error "Validator keystores directory is not accessible",
          path = validatorsDir, err = err.msg
    quit 1

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
  ValidatorConfigFileStatus = enum
    noSuchValidator
    malformedConfigFile

func validatorKeystoreDir(
    validatorsDir: string, pubkey: ValidatorPubKey): string =
  validatorsDir / pubkey.fsName

func feeRecipientPath(validatorsDir: string,
                       pubkey: ValidatorPubKey): string =
  validatorsDir.validatorKeystoreDir(pubkey) / FeeRecipientFilename

func gasLimitPath(validatorsDir: string,
                  pubkey: ValidatorPubKey): string =
  validatorsDir.validatorKeystoreDir(pubkey) / GasLimitFilename

func builderConfigPath(validatorsDir: string,
                        pubkey: ValidatorPubKey): string =
  validatorsDir.validatorKeystoreDir(pubkey) / BuilderConfigPath

from std/strutils import
  cmpIgnoreCase, endsWith, parseBiggestUint, startsWith, strip, toLowerAscii

proc getSuggestedFeeRecipient(
    validatorsDir: string, pubkey: ValidatorPubKey,
    defaultFeeRecipient: Eth1Address):
    Result[Eth1Address, ValidatorConfigFileStatus] =
  # In this particular case, an error might be by design. If the file exists,
  # but doesn't load or parse that is more urgent. People might prefer not to
  # override default suggested fee recipients per validator, so don't warn.
  if not dirExists(validatorsDir.validatorKeystoreDir(pubkey)):
    return err noSuchValidator

  let feeRecipientPath = validatorsDir.feeRecipientPath(pubkey)
  if not fileExists(feeRecipientPath):
    return ok defaultFeeRecipient

  try:
    # Avoid being overly flexible initially. Trailing whitespace is common
    # enough it probably should be allowed, but it is reasonable to simply
    # disallow the mostly-pointless flexibility of leading whitespace.
    ok Eth1Address.fromHex(strutils.strip(
      readFile(feeRecipientPath), leading = false, trailing = true))
  except CatchableError as exc:
    # Because the nonexistent validator case was already checked, any failure
    # at this point is serious enough to alert the user.
    warn "Failed to load fee recipient file; falling back to default fee recipient",
      feeRecipientPath, defaultFeeRecipient,
      err = exc.msg
    err malformedConfigFile

proc getSuggestedGasLimit(
    validatorsDir: string,
    pubkey: ValidatorPubKey,
    defaultGasLimit: uint64): Result[uint64, ValidatorConfigFileStatus] =
  # In this particular case, an error might be by design. If the file exists,
  # but doesn't load or parse that is more urgent. People might prefer not to
  # override their default suggested gas limit per validator, so don't warn.
  if not dirExists(validatorsDir.validatorKeystoreDir(pubkey)):
    return err noSuchValidator

  let gasLimitPath = validatorsDir.gasLimitPath(pubkey)
  if not fileExists(gasLimitPath):
    return ok defaultGasLimit
  try:
    ok parseBiggestUInt(strutils.strip(
      readFile(gasLimitPath), leading = false, trailing = true))
  except SerializationError as e:
    warn "Invalid local gas limit file", gasLimitPath,
      err = e.formatMsg(gasLimitPath)
    err malformedConfigFile
  except CatchableError as exc:
    warn "Failed to load gas limit file; falling back to default gas limit",
      gasLimitPath, defaultGasLimit,
      err = exc.msg
    err malformedConfigFile

type
  BuilderConfig = object
    payloadBuilderEnable: bool
    payloadBuilderUrl: string

proc getBuilderConfig(
    validatorsDir: string, pubkey: ValidatorPubKey,
    defaultBuilderAddress: Opt[string]):
    Result[Opt[string], ValidatorConfigFileStatus] =
  # In this particular case, an error might be by design. If the file exists,
  # but doesn't load or parse that is more urgent. People might prefer not to
  # override default builder configs per validator, so don't warn.
  if not dirExists(validatorsDir.validatorKeystoreDir(pubkey)):
    return err noSuchValidator

  let builderConfigPath = validatorsDir.builderConfigPath(pubkey)
  if not fileExists(builderConfigPath):
    return ok defaultBuilderAddress

  let builderConfig =
    try:
      Json.loadFile(builderConfigPath, BuilderConfig,
                    requireAllFields = true)
    except IOError as err:
      # Any exception must be in the presence of such a file, and therefore
      # an actual error worth logging
      error "Failed to read payload builder configuration", err = err.msg,
            path = builderConfigPath
      return err malformedConfigFile
    except SerializationError as err:
      error "Invalid payload builder configuration",
        err = err.formatMsg(builderConfigPath)
      return err malformedConfigFile

  ok(
    if builderConfig.payloadBuilderEnable:
      Opt.some builderConfig.payloadBuilderUrl
    else:
      Opt.none string)

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

proc loadNetKeystore(keystorePath: string,
                      insecurePwd: Opt[string]): Opt[lcrypto.PrivateKey] =

  if not(checkSensitiveFilePermissions(keystorePath)):
    error "Network keystorage file has insecure permissions",
          key_path = keystorePath
    return

  let keyStore =
    try:
      Json.loadFile(keystorePath, NetKeystore,
                    requireAllFields = true,
                    allowUnknownFields = true)
    except IOError as err:
      error "Failed to read network keystore", err = err.msg,
            path = keystorePath
      return
    except SerializationError as err:
      error "Invalid network keystore", err = err.formatMsg(keystorePath)
      return

  if insecurePwd.isSome():
    warn "Using insecure password to unlock networking key"
    let decrypted = decryptNetKeystore(keyStore,
                                       KeystorePass.init(insecurePwd.get()))
    if decrypted.isOk:
      return ok(decrypted.get())
    else:
      error "Network keystore decryption failed", key_store = keystorePath
      return
  else:
    let prompt = "Please enter passphrase to unlock networking key: "
    let res = keyboardGetPassword[lcrypto.PrivateKey](prompt, 3,
      proc (password: string): KsResult[lcrypto.PrivateKey] =
        let decrypted = decryptNetKeystore(keyStore, KeystorePass.init password)
        if decrypted.isErr():
          error "Keystore decryption failed. Please try again", keystorePath
        decrypted
    )
    if res.isOk():
      ok(res.get())
    else:
      return

proc saveNetKeystore(rng: var HmacDrbgContext, keystorePath: string,
                      netKey: lcrypto.PrivateKey, insecurePwd: Opt[string]
                     ): Result[void, KeystoreGenerationError] =
  let password =
    if insecurePwd.isSome():
      warn "Using insecure password to lock networking key",
           key_path = keystorePath
      insecurePwd.get()
    else:
      let prompt = "Please enter NEW password to lock network key storage: "
      let confirm = "Please confirm, network key storage password: "
      ? keyboardCreatePassword(prompt, confirm).mapErrTo(
        FailedToCreateKeystoreFile)

  let keyStore = createNetKeystore(kdfScrypt, rng, netKey,
                                   KeystorePass.init password)
  let encodedStorage = Json.encode(keyStore)

  let res = secureWriteFile(keystorePath, encodedStorage)
  if res.isOk():
    ok()
  else:
    error "Could not write to network key storage file",
          key_path = keystorePath
    res.mapErrTo(FailedToCreateKeystoreFile)

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

proc createLockedLocalValidatorFiles(
       secretsDir, validatorsDir, keystoreDir,
       secretFile, passwordAsString, keystoreFile,
       encodedStorage: string
     ): Result[FileLockHandle, KeystoreGenerationError] {.raises: [].} =

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
  let lock =
    ? secureWriteLockedFile(keystoreFile,
                            encodedStorage).mapErrTo(FailedToCreateKeystoreFile)

  success = true
  ok(lock)

proc createRemoteValidatorFiles(
       validatorsDir, keystoreDir, keystoreFile, encodedStorage: string
     ): Result[void, KeystoreGenerationError] {.raises: [].} =
  var
    success = false  # becomes true when everything is created successfully

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

  # keystoreFile:
  ? secureWriteFile(keystoreFile,
                    encodedStorage).mapErrTo(FailedToCreateKeystoreFile)
  success = true
  ok()

proc createLockedRemoteValidatorFiles(
       validatorsDir, keystoreDir, keystoreFile, encodedStorage: string
     ): Result[FileLockHandle, KeystoreGenerationError] {.raises: [].} =
  var
    success = false  # becomes true when everything is created successfully

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

  # keystoreFile:
  let lock = ? secureWriteLockedFile(
              keystoreFile, encodedStorage).mapErrTo(FailedToCreateKeystoreFile)
  success = true
  ok(lock)

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

proc saveLockedKeystore(
       rng: var HmacDrbgContext,
       validatorsDir, secretsDir: string,
       signingKey: ValidatorPrivKey,
       signingPubKey: CookedPubKey,
       signingKeyPath: KeyPath,
       password: string,
       mode = Secure
     ): Result[FileLockHandle, KeystoreGenerationError] {.raises: [].} =
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
                                mode = mode)

  let encodedStorage = Json.encode(keyStore)

  let lock = ? createLockedLocalValidatorFiles(secretsDir, validatorsDir,
                                               keystoreDir,
                                               secretsDir / keyName,
                                               keypass.str,
                                               keystoreFile, encodedStorage)
  ok(lock)

proc importKeystore(pool: var ValidatorPool,
                     rng: var HmacDrbgContext,
                     validatorsDir, secretsDir: string,
                     keystore: Keystore,
                     password: string,
                     cache: KeystoreCacheRef): ImportResult[KeystoreData] {.
     raises: [].} =
  let
    keypass = KeystorePass.init(password)
    privateKey = decryptKeystore(keystore, keypass, cache).valueOr:
      return err(AddValidatorFailure.init(AddValidatorStatus.failed, error))
    publicKey = privateKey.toPubKey()
    keyName = publicKey.fsName
    keystoreDir = validatorsDir / keyName

  # We check `publicKey` in memory storage first.
  if publicKey.toPubKey() in pool:
    return err(AddValidatorFailure.init(AddValidatorStatus.existingArtifacts))

  # We check `publicKey` in filesystem.
  if existsKeystore(keystoreDir):
    return err(AddValidatorFailure.init(AddValidatorStatus.existingArtifacts))

  let res = saveLockedKeystore(rng, validatorsDir, secretsDir,
                               privateKey, publicKey, keystore.path, password)

  if res.isErr():
    return err(AddValidatorFailure.init(AddValidatorStatus.failed,
                                        $res.error()))

  ok(KeystoreData.init(privateKey, keystore, res.get()))

func validatorKeystoreDir(host: KeymanagerHost,
                          pubkey: ValidatorPubKey): string =
  host.validatorsDir.validatorKeystoreDir(pubkey)

func feeRecipientPath(host: KeymanagerHost,
                      pubkey: ValidatorPubKey): string =
  host.validatorsDir.feeRecipientPath(pubkey)

func gasLimitPath(host: KeymanagerHost,
                  pubkey: ValidatorPubKey): string =
  host.validatorsDir.gasLimitPath(pubkey)

proc removeFeeRecipientFile(host: KeymanagerHost,
                             pubkey: ValidatorPubKey): Result[void, string] =
  let path = host.feeRecipientPath(pubkey)
  if fileExists(path):
    let res = io2.removeFile(path)
    if res.isErr:
      return err res.error.ioErrorMsg

  return ok()

proc removeGasLimitFile(host: KeymanagerHost,
                         pubkey: ValidatorPubKey): Result[void, string] =
  let path = host.gasLimitPath(pubkey)
  if fileExists(path):
    let res = io2.removeFile(path)
    if res.isErr:
      return err res.error.ioErrorMsg

  return ok()

proc setFeeRecipient(host: KeymanagerHost, pubkey: ValidatorPubKey, feeRecipient: Eth1Address): Result[void, string] =
  let validatorKeystoreDir = host.validatorKeystoreDir(pubkey)

  ? secureCreatePath(validatorKeystoreDir).mapErr(proc(e: auto): string =
    "Could not create wallet directory [" & validatorKeystoreDir & "]: " & $e)

  io2.writeFile(validatorKeystoreDir / FeeRecipientFilename, $feeRecipient)
    .mapErr(proc(e: auto): string = "Failed to write fee recipient file: " & $e)

proc setGasLimit(host: KeymanagerHost,
                  pubkey: ValidatorPubKey,
                  gasLimit: uint64): Result[void, string] =
  let validatorKeystoreDir = host.validatorKeystoreDir(pubkey)

  ? secureCreatePath(validatorKeystoreDir).mapErr(proc(e: auto): string =
    "Could not create wallet directory [" & validatorKeystoreDir & "]: " & $e)

  io2.writeFile(validatorKeystoreDir / GasLimitFilename, $gasLimit)
    .mapErr(proc(e: auto): string = "Failed to write gas limit file: " & $e)

from ".."/spec/beaconstate import has_eth1_withdrawal_credential

proc getValidatorWithdrawalAddress(
    host: KeymanagerHost, pubkey: ValidatorPubKey): Opt[Eth1Address] =
  if host.getValidatorAndIdxFn.isNil:
    Opt.none Eth1Address
  else:
    let validatorAndIndex = host.getValidatorAndIdxFn(pubkey)
    if validatorAndIndex.isNone:
      Opt.none Eth1Address
    else:
      template validator: auto = validatorAndIndex.get.validator
      if has_eth1_withdrawal_credential(validator):
        var address: distinctBase(Eth1Address)
        address[0..^1] =
          validator.withdrawal_credentials.data[12..^1]
        Opt.some Eth1Address address
      else:
        Opt.none Eth1Address

func getPerValidatorDefaultFeeRecipient(
    defaultFeeRecipient: Opt[Eth1Address],
    withdrawalAddress: Opt[Eth1Address]): Eth1Address =
  defaultFeeRecipient.valueOr:
    withdrawalAddress.valueOr:
      (static(default(Eth1Address)))

proc getSuggestedFeeRecipient(
    host: KeymanagerHost, pubkey: ValidatorPubKey,
    defaultFeeRecipient: Eth1Address):
    Result[Eth1Address, ValidatorConfigFileStatus] =
  host.validatorsDir.getSuggestedFeeRecipient(pubkey, defaultFeeRecipient)

proc getSuggestedFeeRecipient(
    host: KeymanagerHost, pubkey: ValidatorPubKey,
    withdrawalAddress: Opt[Eth1Address]): Eth1Address =
  # Enforce the gsfr(foo).valueOr(foo) pattern where feasible
  let perValidatorDefaultFeeRecipient = getPerValidatorDefaultFeeRecipient(
      host.defaultFeeRecipient, withdrawalAddress)
  host.getSuggestedFeeRecipient(
      pubkey, perValidatorDefaultFeeRecipient).valueOr:
    perValidatorDefaultFeeRecipient

proc getSuggestedGasLimit(
    host: KeymanagerHost,
    pubkey: ValidatorPubKey): Result[uint64, ValidatorConfigFileStatus] =
  host.validatorsDir.getSuggestedGasLimit(pubkey, host.defaultGasLimit)

proc getBuilderConfig(
    host: KeymanagerHost, pubkey: ValidatorPubKey):
    Result[Opt[string], ValidatorConfigFileStatus] =
  host.validatorsDir.getBuilderConfig(pubkey, host.defaultBuilderAddress)

proc addValidator(
    host: KeymanagerHost, keystore: KeystoreData,
    withdrawalAddress: Opt[Eth1Address]) =
  let
    feeRecipient = host.getSuggestedFeeRecipient(
      keystore.pubkey, withdrawalAddress)
    gasLimit = host.getSuggestedGasLimit(keystore.pubkey).valueOr(
      host.defaultGasLimit)
    v = host.validatorPool[].addValidator(keystore, feeRecipient, gasLimit)

  if not isNil(host.getValidatorAndIdxFn):
    let data = host.getValidatorAndIdxFn(keystore.pubkey)
    v.updateValidator(data)

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

proc saveWallet(wallet: Wallet, outWalletPath: string): Result[void, string] =
  let
    walletDir = splitFile(outWalletPath).dir
    encodedWallet = Json.encode(wallet, pretty = true)

  ? secureCreatePath(walletDir).mapErr(proc(e: auto): string =
    "Could not create wallet directory [" & walletDir & "]: " & $e)

  ? secureWriteFile(outWalletPath, encodedWallet).mapErr(proc(e: auto): string =
    "Could not write wallet to file [" & outWalletPath & "]: " & $e)

  ok()

proc saveWallet(wallet: WalletPathPair): Result[void, string] =
  saveWallet(wallet.wallet, wallet.path)

proc readPasswordInput(prompt: string, password: var string): bool =
  burnMem password
  try:
    when defined(windows):
      # readPasswordFromStdin() on Windows always returns `false`.
      # https://github.com/nim-lang/Nim/issues/15207
      discard readPasswordFromStdin(prompt, password)
      true
    else:
      readPasswordFromStdin(prompt, password)
  except IOError:
    false

proc setStyleNoError(styles: set[Style]) =
  when defined(windows):
    try: stdout.setStyle(styles)
    except: discard
  else:
    try: stdout.setStyle(styles)
    except IOError, ValueError: discard

proc setForegroundColorNoError(color: ForegroundColor) =
  when defined(windows):
    try: stdout.setForegroundColor(color)
    except: discard
  else:
    try: stdout.setForegroundColor(color)
    except IOError, ValueError: discard

proc resetAttributesNoError() =
  when defined(windows):
    try: stdout.resetAttributes()
    except: discard
  else:
    try: stdout.resetAttributes()
    except IOError: discard

proc importKeystoreFromFile(
    decryptor: var MultipleKeystoresDecryptor,
    fileName: string
  ): Result[ValidatorPrivKey, string] =
  let
    data = readAllChars(fileName).valueOr:
      return err("Unable to read keystore file [" & ioErrorMsg(error) & "]")
    keystore =
      try:
        parseKeystore(data)
      except SerializationError as e:
        return err("Invalid keystore file format [" &
                   e.formatMsg(fileName) & "]")

  var firstDecryptionAttempt = true
  while true:
    var secret: seq[byte]
    let status = decryptCryptoField(
      keystore.crypto,
      KeystorePass.init(decryptor.previouslyUsedPassword),
      secret)
    case status
    of DecryptionStatus.Success:
      let privateKey = ValidatorPrivKey.fromRaw(secret).valueOr:
        return err("Keystore holds invalid private key [" & $error & "]")
      return ok(privateKey)
    else:
      return err("Invalid keystore format")

proc importKeystoresFromDir(rng: var HmacDrbgContext, meth: ImportMethod,
                             importedDir, validatorsDir, secretsDir: string) =
  var password: string  # TODO consider using a SecretString type
  defer: burnMem(password)

  var (singleSaltPassword, singleSaltSalt) =
    case meth
    of ImportMethod.Normal:
      var defaultSeq: seq[byte]
      (KeystorePass.init(""), defaultSeq)
    of ImportMethod.SingleSalt:
      (KeystorePass.init(ncrutils.toHex(rng.generateBytes(32))),
       rng.generateBytes(32))

  defer:
    burnMem(singleSaltPassword)
    burnMem(singleSaltSalt)

  try:
    for file in walkDirRec(importedDir):
      let filenameParts = splitFile(file)
      if toLowerAscii(filenameParts.ext) != ".json":
        continue

      # In case we are importing from eth2.0-deposits-cli, the imported
      # validator_keys directory will also include a "deposit_data" file
      # intended for uploading to the launchpad. We'll skip it to avoid
      # the "Invalid keystore" warning that it will trigger.
      if filenameParts.name.startsWith("deposit_data"):
        continue

      let keystore =
        try:
          Json.loadFile(file, Keystore,
                        requireAllFields = true,
                        allowUnknownFields = true)
        except SerializationError as e:
          warn "Invalid keystore", err = e.formatMsg(file)
          continue
        except IOError as e:
          warn "Failed to read keystore file", file, err = e.msg
          continue

      var firstDecryptionAttempt = true

      while true:
        var secret: seq[byte]
        let status = decryptCryptoField(keystore.crypto,
                                        KeystorePass.init password,
                                        secret)
        case status
        of DecryptionStatus.Success:
          let privKey = ValidatorPrivKey.fromRaw(secret)
          if privKey.isOk:
            let pubkey = privKey.value.toPubKey
            var (password, salt) =
              case meth
              of ImportMethod.Normal:
                var defaultSeq: seq[byte]
                (KeystorePass.init ncrutils.toHex(rng.generateBytes(32)),
                 defaultSeq)
              of ImportMethod.SingleSalt:
                (singleSaltPassword, singleSaltSalt)

            defer:
              burnMem(password)
              burnMem(salt)

            let status = saveKeystore(rng, validatorsDir, secretsDir,
                                      privKey.value, pubkey,
                                      keystore.path, password.str,
                                      salt)
            if status.isOk:
              notice "Keystore imported", file
            else:
              error "Failed to import keystore",
                file, validatorsDir, secretsDir, err = status.error
          else:
            error "Imported keystore holds invalid key", file, err = privKey.error
          break
        of DecryptionStatus.InvalidKeystore:
          warn "Invalid keystore", file
          break
        of DecryptionStatus.InvalidPassword:
          if firstDecryptionAttempt:
            try:
              const msg = "Please enter the password for decrypting '$1' " &
                          "or press ENTER to skip importing this keystore"
            except ValueError:
              raiseAssert "The format string above is correct"
          else:
            echo "The entered password was incorrect. Please try again."
          firstDecryptionAttempt = false

          if not readPasswordInput("Password: ", password):
            echo "System error while entering password. Please try again."

          if password.len == 0:
            break
  except OSError:
    fatal "Failed to access the imported deposits directory"
    quit 1

template ask(prompt: string): string =
  try:
    stdout.write prompt, ": "
    stdin.readLine()
  except IOError:
    return err "failure to read data from stdin"

template clearScreen =
  echo "\e[1;1H\e[2J\e[3J"

import std/strutils

proc loadWallet(fileName: string): Result[Wallet, string] =
  try:
    ok Json.loadFile(fileName, Wallet)
  except SerializationError as err:
    err "Invalid wallet syntax: " & err.formatMsg(fileName)
  except IOError as err:
    err "Error accessing wallet file \"" & fileName & "\": " & err.msg

proc findWallet(config: BeaconNodeConf,
                 name: WalletName): Result[Opt[WalletPathPair], string] =
  var walletFiles = newSeq[string]()
  try:
    for kind, walletFile in walkDir(config.walletsDir):
      if kind != pcFile: continue
      let walletId = splitFile(walletFile).name
      if cmpIgnoreCase(walletId, name.string) == 0:
        let wallet = ? loadWallet(walletFile)
        return ok Opt.some WalletPathPair(wallet: wallet, path: walletFile)
      walletFiles.add walletFile
  except OSError as err:
    return err("Error accessing the wallets directory \"" &
                config.walletsDir & "\": " & err.msg)

  for walletFile in walletFiles:
    let wallet = ? loadWallet(walletFile)
    if cmpIgnoreCase(wallet.name.string, name.string) == 0 or
       cmpIgnoreCase(wallet.uuid.string, name.string) == 0:
      return ok Opt.some WalletPathPair(wallet: wallet, path: walletFile)

  return ok Opt.none(WalletPathPair)

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
