# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[os, strutils, terminal, wordwrap, unicode],
  chronicles, chronos, json_serialization, zxcvbn,
  serialization, blscurve, eth/common/eth_types, eth/keys, confutils, bearssl,
  nimbus_security_resources,
  ".."/spec/[eth2_merkleization, keystore, crypto],
  ".."/spec/datatypes/base,
  stew/io2, libp2p/crypto/crypto as lcrypto,
  nimcrypto/utils as ncrutils,
  ".."/[conf, filepath],
  ".."/networking/network_metadata,
  ./validator_pool

export
  keystore, validator_pool, crypto

when defined(windows):
  import stew/[windows/acl]

{.localPassC: "-fno-lto".} # no LTO for crypto

const
  KeystoreFileName* = "keystore.json"
  RemoteKeystoreFileName* = "remote_keystore.json"
  NetKeystoreFileName* = "network_keystore.json"
  DisableFileName* = ".disable"
  DisableFileContent* = "Please do not remove this file manually. " &
                        "This can lead to slashing of this validator's key."
  KeyNameSize* = 98 # 0x + hexadecimal key representation 96 characters.

type
  WalletPathPair* = object
    wallet*: Wallet
    path*: string

  CreatedWallet* = object
    walletPath*: WalletPathPair
    seed*: KeySeed

  AnyConf* = BeaconNodeConf | ValidatorClientConf | SigningNodeConf

  KmResult*[T] = Result[T, cstring]

  RemoveValidatorStatus* {.pure.} = enum
    deleted = "Deleted"
    notFound = "Not found"

  AddValidatorStatus* {.pure.} = enum
    existingArtifacts = "Keystore artifacts already exists"
    failed = "Validator not added"

  AddValidatorFailure* = object
    status*: AddValidatorStatus
    message*: string

  ImportResult*[T] = Result[T, AddValidatorFailure]

const
  minPasswordLen = 12
  minPasswordEntropy = 60.0

  mostCommonPasswords = wordListArray(
    nimbusSecurityResourcesPath /
      "passwords" / "10-million-password-list-top-100000.txt",
    minWordLen = minPasswordLen)

proc echoP*(msg: string) =
  ## Prints a paragraph aligned to 80 columns
  echo ""
  echo wrapWords(msg, 80)

func init*(T: type KeystoreData,
           privateKey: ValidatorPrivKey,
           keystore: Keystore): T =
  KeystoreData(
    kind: KeystoreKind.Local,
    privateKey: privateKey,
    description: if keystore.description == nil: none(string)
                 else: some(keystore.description[]),
    path: keystore.path,
    uuid: keystore.uuid,
    version: uint64(keystore.version),
    pubkey: privateKey.toPubKey().toPubKey()
  )

func init*(T: type KeystoreData,
           keystore: RemoteKeystore): Result[T, cstring] =
  let cookedKey =
    block:
      let res = keystore.pubkey.load()
      if res.isNone():
        return err("Invalid validator's public key")
      res.get()
  ok KeystoreData(
    kind: KeystoreKind.Remote,
    pubkey: cookedKey.toPubKey,
    description: keystore.description,
    version: keystore.version,
    remotes: keystore.remotes,
    threshold: keystore.threshold
  )

func init*(T: type KeystoreData, cookedKey: CookedPubKey,
           remotes: seq[RemoteSignerInfo], threshold: uint32): T =
  KeystoreData(
    kind: KeystoreKind.Remote,
    pubkey: cookedKey.toPubKey(),
    version: 2'u64,
    remotes: remotes,
    threshold: threshold
  )

func init(T: type AddValidatorFailure, status: AddValidatorStatus,
          msg = ""): AddValidatorFailure {.raises: [Defect].} =
  AddValidatorFailure(status: status, message: msg)

func toKeystoreKind*(kind: ValidatorKind): KeystoreKind {.raises: [Defect].} =
  case kind
  of ValidatorKind.Local:
    KeystoreKind.Local
  of ValidatorKind.Remote:
    KeystoreKind.Remote

proc checkAndCreateDataDir*(dataDir: string): bool =
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
                data_dir = dataDir,
                current_permissions = currPerms.toOct(4),
                required_permissions = requiredPerms.toOct(4)
          let newPermsRes = setPermissions(dataDir, requiredPerms)
          if newPermsRes.isErr():
            fatal "Could not set data directory permissions",
                   data_dir = dataDir,
                   errorCode = $newPermsRes.error,
                   errorMsg = ioErrorMsg(newPermsRes.error),
                   old_permissions = currPerms.toOct(4),
                   new_permissions = requiredPerms.toOct(4)
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

proc checkSensitivePathPermissions*(dirFilePath: string): bool =
  ## If ``dirFilePath`` is file, then check if file has only
  ##
  ##   - "(600) rwx------" permissions on Posix (Linux, MacOS, BSD)
  ##   - current user only ACL on Windows
  ##
  ## If ``dirFilePath`` is directory, then check if directory has only
  ##
  ##   - "(700) rwx------" permissions on Posix (Linux, MacOS, BSD)
  ##   - current user only ACL on Windows
  ##
  ## Procedure returns ``true`` if directory/file is present and all required
  ## permissions are set.
  let r1 = isDir(dirFilePath)
  let r2 = isFile(dirFilePath)
  if r1 or r2:
    when defined(windows):
      let res = checkCurrentUserOnlyACL(dirFilePath)
      if res.isErr():
        false
      else:
        if res.get() == false:
          false
        else:
          true
    else:
      let requiredPermissions = if r1: 0o700 else: 0o600
      let res = getPermissions(dirFilePath)
      if res.isErr():
        false
      else:
        if res.get() != requiredPermissions:
          false
        else:
          true
  else:
    false

proc checkSensitiveFilePermissions*(filePath: string): bool =
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
              key_path = filePath,
              current_permissions = currPerms.toOct(4),
              required_permissions = requiredPerms.toOct(4)
        let newPermsRes = setPermissions(filePath, requiredPerms)
        if newPermsRes.isErr():
          fatal "Could not set data directory permissions",
                 key_path = filePath,
                 errorCode = $newPermsRes.error,
                 errorMsg = ioErrorMsg(newPermsRes.error),
                 old_permissions = currPerms.toOct(4),
                 new_permissions = requiredPerms.toOct(4)
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
      elif password in mostCommonPasswords:
        echoP "The entered password is too commonly used and it would be " &
              "easy to brute-force with automated tools."
        echo ""
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
     gcsafe, raises: [Defect].}): KsResult[T] =
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

proc loadKeystoreFile*(path: string): KsResult[Keystore] {.
     raises: [Defect].} =
  try:
    ok(Json.loadFile(path, Keystore))
  except IOError as err:
    return err("Could not read keystore file")
  except SerializationError as err:
    return err("Could not decode keystore file: " & err.formatMsg(path))

proc loadSecretFile*(path: string): KsResult[KeystorePass] {.
     raises: [Defect].} =
  try:
    ok(KeystorePass.init(readFile(path)))
  except IOError:
    return err("Could not read password file")

proc loadKeystoreUnsafe*(validatorsDir, secretsDir,
                         keyName: string): KsResult[KeystoreData] =
  ## Load keystore without any checks on keystore/secret permissions.
  let
    keystorePath = validatorsDir / keyName / KeystoreFileName
    keystore = ? loadKeystoreFile(keystorePath)

  let
    passphrasePath = secretsDir / keyName
    passphrase = ? loadSecretFile(passphrasePath)

  let res = decryptKeystore(keystore, passphrase)
  if res.isOk():
    ok(KeystoreData.init(res.get(), keystore))
  else:
    err("Failed to decrypt keystore")

proc loadRemoteKeystoreImpl(validatorsDir,
                            keyName: string): Option[KeystoreData] =
  let keystorePath = validatorsDir / keyName / RemoteKeystoreFileName

  if not(checkSensitiveFilePermissions(keystorePath)):
    error "Remote keystorage file has insecure permissions",
          key_path = keystorePath
    return

  let keyStore =
    block:
      let remoteKeystore =
        try:
          Json.loadFile(keystorePath, RemoteKeystore)
        except IOError as err:
          error "Failed to read remote keystore file", err = err.msg,
                path = keystorePath
          return
        except SerializationError as e:
          error "Invalid remote keystore file",
                path = keystorePath,
                err_msg = e.formatMsg(keystorePath)
          return
      let res = init(KeystoreData, remoteKeystore)
      if res.isErr():
        error "Invalid remote keystore file",
              path = keystorePath
        return
      res.get()
  some(keyStore)

proc loadKeystoreImpl(validatorsDir, secretsDir, keyName: string,
                      nonInteractive: bool): Option[KeystoreData] =
  let
    keystorePath = validatorsDir / keyName / KeystoreFileName
    keystore =
      block:
        let res = loadKeystoreFile(keystorePath)
        if res.isErr():
          error "Failed to read keystore file", error = res.error(),
                path = keystorePath
          return
        res.get()

  let passphrasePath = secretsDir / keyName
  if fileExists(passphrasePath):
    if not(checkSensitiveFilePermissions(passphrasePath)):
      error "Password file has insecure permissions", key_path = keystorePath
      return

    let passphrase =
      block:
        let res = loadSecretFile(passphrasePath)
        if res.isErr():
          error "Failed to read passphrase file", err = res.error(),
                path = passphrasePath
          return
        res.get()

    let res = decryptKeystore(keystore, passphrase)
    if res.isOk():
      return some(KeystoreData.init(res.get(), keystore))
    else:
      error "Failed to decrypt keystore", keystorePath, passphrasePath
      return

  if nonInteractive:
    error "Unable to load validator key store. Please ensure matching passphrase exists in the secrets dir",
      keyName, validatorsDir, secretsDir = secretsDir
    return

  let prompt = "Please enter passphrase for key \"" &
               (validatorsDir / keyName) & "\": "
  let res = keyboardGetPassword[ValidatorPrivKey](prompt, 3,
    proc (password: string): KsResult[ValidatorPrivKey] =
      let decrypted = decryptKeystore(keystore, KeystorePass.init password)
      if decrypted.isErr():
        error "Keystore decryption failed. Please try again", keystorePath
      decrypted
  )

  if res.isOk():
    some(KeystoreData.init(res.get(), keystore))
  else:
    return

proc loadKeystore*(validatorsDir, secretsDir, keyName: string,
                   nonInteractive: bool): Option[KeystoreData] =
  let
    keystorePath = validatorsDir / keyName
    localKeystorePath = keystorePath / KeystoreFileName
    remoteKeystorePath = keystorePath / RemoteKeystoreFileName

  if fileExists(localKeystorePath):
    loadKeystoreImpl(validatorsDir, secretsDir, keyName, nonInteractive)
  elif fileExists(remoteKeystorePath):
    loadRemoteKeystoreImpl(validatorsDir, keyName)
  else:
    error "Unable to find any keystore files", keystorePath
    none[KeystoreData]()

proc removeValidatorFiles*(validatorsDir, secretsDir, keyName: string,
                           kind: KeystoreKind
                          ): KmResult[RemoveValidatorStatus] {.
     raises: [Defect].} =
  let
    keystoreDir = validatorsDir / keyName
    keystoreFile =
      case kind
      of KeystoreKind.Local:
        keystoreDir / KeystoreFileName
      of KeystoreKind.Remote:
        keystoreDir / RemoteKeystoreFileName
    secretFile = secretsDir / keyName

  if not(dirExists(keystoreDir)):
    return ok(RemoveValidatorStatus.notFound)

  if not(fileExists(keystoreFile)):
    return ok(RemoveValidatorStatus.notFound)

  case kind
  of KeystoreKind.Local:
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
  of KeystoreKind.Remote:
    block:
      let res = io2.removeFile(keystoreFile)
      if res.isErr():
        return err("Could not remove keystore file")
    # We remove folder with all subfolders and files inside.
    try:
      removeDir(keystoreDir, false)
    except OSError:
      return err("Could not remove keystore directory")

  ok(RemoveValidatorStatus.deleted)

proc removeValidatorFiles*(conf: AnyConf, keyName: string,
                           kind: KeystoreKind): KmResult[RemoveValidatorStatus]
                          {.raises: [Defect].} =
  removeValidatorFiles(conf.validatorsDir(), conf.secretsDir(), keyName, kind)

proc removeValidator*(pool: var ValidatorPool, conf: AnyConf,
                      publicKey: ValidatorPubKey,
                      kind: KeystoreKind): KmResult[RemoveValidatorStatus]
                     {.raises: [Defect].} =
  let validator = pool.getValidator(publicKey)
  if isNil(validator):
    return ok(RemoveValidatorStatus.notFound)
  if validator.kind.toKeystoreKind() != kind:
    return ok(RemoveValidatorStatus.notFound)
  let publicKeyName: string = "0x" & publicKey.toHex()
  let res = removeValidatorFiles(conf, publicKeyName, kind)
  if res.isErr():
    return err(res.error())
  pool.removeValidator(publicKey)
  ok(res.value())

proc checkKeyName*(keyName: string): bool =
  const keyAlphabet = {'a'..'f', 'A'..'F', '0'..'9'}
  if len(keyName) != KeyNameSize:
    return false
  if keyName[0] != '0' and keyName[1] != 'x':
    return false
  for index in 2 ..< len(keyName):
    if keyName[index] notin keyAlphabet:
      return false
  true

proc existsKeystore*(keystoreDir: string, keyKind: KeystoreKind): bool {.
     raises: [Defect].} =
  case keyKind
  of KeystoreKind.Local:
    fileExists(keystoreDir / KeystoreFileName)
  of KeystoreKind.Remote:
    fileExists(keystoreDir / RemoteKeystoreFileName)

proc existsKeystore*(keystoreDir: string,
                     keysMask: set[KeystoreKind]): bool {.raises: [Defect].} =
  if KeystoreKind.Local in keysMask:
    if existsKeystore(keystoreDir, KeystoreKind.Local):
      return true
  if KeystoreKind.Remote in keysMask:
    if existsKeystore(keystoreDir, KeystoreKind.Remote):
      return true
  false

iterator listLoadableKeystores*(validatorsDir, secretsDir: string,
                                nonInteractive: bool,
                                keysMask: set[KeystoreKind]): KeystoreData =
  try:
    for kind, file in walkDir(validatorsDir):
      if kind == pcDir:

        let
          keyName = splitFile(file).name
          keystoreDir = validatorsDir / keyName
          keystoreFile = keystoreDir / KeystoreFileName

        if not(checkKeyName(keyName)):
          # Skip folders which name do not satisfy "0x[a-fA-F0-9]{96, 96}".
          continue

        if not(existsKeystore(keystoreDir, keysMask)):
          # Skip folders which do not have keystore file inside.
          continue

        let
          secretFile = secretsDir / keyName
          keystore = loadKeystore(validatorsDir, secretsDir, keyName,
                                  nonInteractive)
        if keystore.isSome():
          yield keystore.get()
        else:
          fatal "Unable to load keystore", keystore = file
          quit 1

  except OSError as err:
    error "Validator keystores directory not accessible",
          path = validatorsDir, err = err.msg
    quit 1

iterator listLoadableKeystores*(config: AnyConf): KeystoreData =
  for el in listLoadableKeystores(config.validatorsDir(),
                                  config.secretsDir(),
                                  config.nonInteractive,
                                  {KeystoreKind.Local, KeystoreKind.Remote}):
    yield el

type
  KeystoreGenerationErrorKind* = enum
    FailedToCreateValidatorsDir
    FailedToCreateKeystoreDir
    FailedToCreateSecretsDir
    FailedToCreateSecretFile
    FailedToCreateKeystoreFile
    DuplicateKeystoreDir
    DuplicateKeystoreFile

  KeystoreGenerationError* = object
    case kind*: KeystoreGenerationErrorKind
    of FailedToCreateKeystoreDir,
       FailedToCreateValidatorsDir,
       FailedToCreateSecretsDir,
       FailedToCreateSecretFile,
       FailedToCreateKeystoreFile,
       DuplicateKeystoreDir,
       DuplicateKeystoreFile:
      error*: string

proc mapErrTo*[T, E](r: Result[T, E], v: static KeystoreGenerationErrorKind):
    Result[T, KeystoreGenerationError] =
  r.mapErr(proc (e: E): KeystoreGenerationError =
    KeystoreGenerationError(kind: v, error: $e))

proc loadNetKeystore*(keystorePath: string,
                      insecurePwd: Option[string]): Option[lcrypto.PrivateKey] =

  if not(checkSensitiveFilePermissions(keystorePath)):
    error "Network keystorage file has insecure permissions",
          key_path = keystorePath
    return

  let keyStore =
    try:
      Json.loadFile(keystorePath, NetKeystore)
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
      return some(decrypted.get())
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
      some(res.get())
    else:
      return

proc saveNetKeystore*(rng: var BrHmacDrbgContext, keystorePath: string,
                      netKey: lcrypto.PrivateKey, insecurePwd: Option[string]
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
  var encodedStorage: string
  try:
    encodedStorage = Json.encode(keyStore)
  except SerializationError as exc:
    error "Could not serialize network key storage", key_path = keystorePath
    return err(KeystoreGenerationError(
      kind: FailedToCreateKeystoreFile, error: exc.msg))

  let res = secureWriteFile(keystorePath, encodedStorage)
  if res.isOk():
    ok()
  else:
    error "Could not write to network key storage file",
          key_path = keystorePath
    res.mapErrTo(FailedToCreateKeystoreFile)

proc createValidatorFiles*(secretsDir, validatorsDir, keystoreDir, secretFile,
                           passwordAsString, keystoreFile,
                           encodedStorage: string
                          ): Result[void, KeystoreGenerationError] =

  var
    success = false # becomes true when everything is created successfully
    cleanupSecretsDir = true # becomes false if secretsDir already existed
    cleanupValidatorsDir = true # becomes false if validatorsDir already existed

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

proc createValidatorFiles*(validatorsDir, keystoreDir, keystoreFile,
                           encodedStorage: string
                          ): Result[void, KeystoreGenerationError] =
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

proc saveKeystore*(rng: var BrHmacDrbgContext,
                   validatorsDir, secretsDir: string,
                   signingKey: ValidatorPrivKey,
                   signingPubKey: CookedPubKey,
                   signingKeyPath: KeyPath,
                   password: string,
                   mode = Secure): Result[void, KeystoreGenerationError] =
  let
    keypass = KeystorePass.init(password)
    keyName = "0x" & signingPubKey.toHex()
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

  var encodedStorage: string
  try:
    encodedStorage = Json.encode(keyStore)
  except SerializationError as e:
    error "Could not serialize keystorage", key_path = keystoreFile
    return err(KeystoreGenerationError(
      kind: FailedToCreateKeystoreFile, error: e.msg))

  ? createValidatorFiles(secretsDir, validatorsDir,
                         keystoreDir,
                         secretsDir / keyName, keypass.str,
                         keystoreFile, encodedStorage)

  ok()

proc saveKeystore*(validatorsDir: string,
                   publicKey: ValidatorPubKey,
                   urls: seq[RemoteSignerInfo],
                   threshold: uint32,
                   flags: set[RemoteKeystoreFlag] = {},
                   remoteType = RemoteSignerType.Web3Signer,
                   desc = ""): Result[void, KeystoreGenerationError]
                  {.raises: [Defect].} =
  let
    keyName = "0x" & publicKey.toHex()
    keystoreDir = validatorsDir / keyName
    keystoreFile = keystoreDir / RemoteKeystoreFileName
    keystoreDesc = if len(desc) == 0: none[string]() else: some(desc)
    keyStore = RemoteKeystore(
      version: 2'u64,
      description: keystoreDesc,
      remoteType: remoteType,
      pubkey: publicKey,
      threshold: threshold,
      remotes: urls,
      flags: flags)

  if dirExists(keystoreDir):
    return err(KeystoreGenerationError(kind: DuplicateKeystoreDir,
      error: "Keystore directory already exists"))
  if fileExists(keystoreFile):
    return err(KeystoreGenerationError(kind: DuplicateKeystoreFile,
      error: "Keystore file already exists"))

  let encodedStorage =
    try:
      Json.encode(keyStore)
    except SerializationError as exc:
      error "Could not serialize keystorage", key_path = keystoreFile
      return err(KeystoreGenerationError(
        kind: FailedToCreateKeystoreFile, error: exc.msg))

  ? createValidatorFiles(validatorsDir, keystoreDir, keystoreFile,
                         encodedStorage)
  ok()

proc saveKeystore*(validatorsDir: string,
                   publicKey: ValidatorPubKey,
                   url:  HttpHostUri): Result[void, KeystoreGenerationError]
                  {.raises: [Defect].} =
  let remoteInfo = RemoteSignerInfo(url: url, id: 0)
  saveKeystore(validatorsDir, publicKey, @[remoteInfo], 1)

proc saveKeystore*(conf: AnyConf,
                   publicKey: ValidatorPubKey,
                   remotes: seq[RemoteSignerInfo],
                   threshold: uint32,
                   flags: set[RemoteKeystoreFlag] = {},
                   remoteType = RemoteSignerType.Web3Signer,
                   desc = ""): Result[void, KeystoreGenerationError]
                  {.raises: [Defect].} =
  saveKeystore(
    conf.validatorsDir(),
    publicKey, remotes, threshold, flags, remoteType, desc)

proc importKeystore*(pool: var ValidatorPool, conf: AnyConf,
                     keystore: RemoteKeystore): ImportResult[KeystoreData]
                    {.raises: [Defect].} =
  let
    publicKey = keystore.pubkey
    keyName = "0x" & publicKey.toHex()
    validatorsDir = conf.validatorsDir()
    keystoreDir = validatorsDir / keyName
    keystoreFile = keystoreDir / RemoteKeystoreFileName

  # We check `publicKey`.
  let cookedKey =
    block:
      let res = publicKey.load()
      if res.isNone():
        return err(
          AddValidatorFailure.init(AddValidatorStatus.failed,
                                   "Invalid validator's public key"))
      res.get()

  # We check `publicKey` in memory storage first.
  if publicKey in pool:
    return err(AddValidatorFailure.init(AddValidatorStatus.existingArtifacts))

  # We check `publicKey` in filesystem.
  if existsKeystore(keystoreDir, {KeystoreKind.Local, KeystoreKind.Remote}):
    return err(AddValidatorFailure.init(AddValidatorStatus.existingArtifacts))

  let res = saveKeystore(conf, publicKey, keystore.remotes, keystore.threshold)
  if res.isErr():
    return err(AddValidatorFailure.init(AddValidatorStatus.failed,
                                        $res.error()))
  ok(KeystoreData.init(cookedKey, keystore.remotes, keystore.threshold))

proc importKeystore*(pool: var ValidatorPool,
                     rng: var BrHmacDrbgContext,
                     conf: AnyConf, keystore: Keystore,
                     password: string): ImportResult[KeystoreData] {.
     raises: [Defect].} =
  let keypass = KeystorePass.init(password)
  let privateKey =
    block:
      let res = decryptKeystore(keystore, keypass)
      if res.isOk():
        res.get()
      else:
        return err(
          AddValidatorFailure.init(AddValidatorStatus.failed, res.error()))
  let
    publicKey = privateKey.toPubKey()
    keyName = "0x" & publicKey.toHex()
    validatorsDir = conf.validatorsDir()
    secretsDir = conf.secretsDir()
    secretFile = secretsDir / keyName
    keystoreDir = validatorsDir / keyName
    keystoreFile = keystoreDir / KeystoreFileName

  # We check `publicKey` in memory storage first.
  if publicKey.toPubKey() in pool:
    return err(AddValidatorFailure.init(AddValidatorStatus.existingArtifacts))

  # We check `publicKey` in filesystem.
  if existsKeystore(keystoreDir, {KeystoreKind.Local, KeystoreKind.Remote}):
    return err(AddValidatorFailure.init(AddValidatorStatus.existingArtifacts))

  let res = saveKeystore(rng, validatorsDir, secretsDir,
                         privateKey, publicKey, keystore.path, password)

  if res.isErr():
    return err(AddValidatorFailure.init(AddValidatorStatus.failed,
                                        $res.error()))

  ok(KeystoreData.init(privateKey, keystore))

proc generateDistirbutedStore*(rng: var BrHmacDrbgContext,
                               shares: seq[SecretShare],
                               pubKey: ValidatorPubKey,
                               validatorIdx: Natural,
                               shareSecretsDir: string,
                               shareValidatorDir: string,
                               remoteValidatorDir: string,
                               remoteSignersUrls: seq[string],
                               threshold: uint32): Result[void, KeystoreGenerationError] =
  var signers: seq[RemoteSignerInfo]
  for idx, share in shares:
    var password = KeystorePass.init ncrutils.toHex(getRandomBytes(rng, 32))
    # remote signer shares
    defer: burnMem(password)
    ? saveKeystore(rng,
                   shareValidatorDir / $share.id,
                   shareSecretsDir / $share.id,
                   share.key, share.key.toPubKey,
                   makeKeyPath(validatorIdx, signingKeyKind),
                   password.str,
                   KeystoreMode.Secure)

    signers.add RemoteSignerInfo(
      url: HttpHostUri(parseUri(remoteSignersUrls[idx])),
      id: share.id,
      pubkey: share.key.toPubKey.toPubKey)

  # actual validator
  saveKeystore(remoteValidatorDir, pubKey, signers, threshold)

proc generateDeposits*(cfg: RuntimeConfig,
                       rng: var BrHmacDrbgContext,
                       seed: KeySeed,
                       firstValidatorIdx, totalNewValidators: int,
                       validatorsDir: string,
                       secretsDir: string,
                       remoteSignersUrls: seq[string] = @[],
                       threshold: uint32 = 1,
                       remoteValidatorsCount: uint32 = 0,
                       mode = Secure): Result[seq[DepositData],
                                              KeystoreGenerationError] =
  var deposits: seq[DepositData]

  notice "Generating deposits", totalNewValidators, validatorsDir, secretsDir

  # We'll reuse a single variable here to make the secret
  # scrubbing (burnMem) easier to handle:
  var baseKey = deriveMasterKey(seed)
  defer: burnMem(baseKey)
  baseKey = deriveChildKey(baseKey, baseKeyPath)

  let localValidatorsCount = totalNewValidators - int(remoteValidatorsCount)
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

    var password = KeystorePass.init ncrutils.toHex(getRandomBytes(rng, 32))
    defer: burnMem(password)
    ? saveKeystore(rng, validatorsDir, secretsDir,
                   derivedKey, signingPubKey,
                   makeKeyPath(validatorIdx, signingKeyKind), password.str,
                   mode)

    deposits.add prepareDeposit(
      cfg, withdrawalPubKey, derivedKey, signingPubKey)

  for i in 0 ..< remoteValidatorsCount:
    let validatorIdx = int(firstValidatorIdx) + localValidatorsCount + int(i)

    # We'll reuse a single variable here to make the secret
    # scrubbing (burnMem) easier to handle:
    var derivedKey = baseKey
    defer: burnMem(derivedKey)
    derivedKey = deriveChildKey(derivedKey, validatorIdx)
    derivedKey = deriveChildKey(derivedKey, 0) # This is witdrawal key
    let withdrawalPubKey = derivedKey.toPubKey
    derivedKey = deriveChildKey(derivedKey, 0) # This is the signing key
    let signingPubKey = derivedKey.toPubKey

    let sharesCount = uint32 len(remoteSignersUrls)

    let shares = generateSecretShares(derivedKey, rng, threshold, sharesCount)
    if shares.isErr():
      error "Failed to generate distributed key: ", threshold, sharesCount
      continue

    ? generateDistirbutedStore(rng,
                               shares.get,
                               signingPubKey.toPubKey,
                               validatorIdx,
                               secretsDir & "_shares",
                               validatorsDir & "_shares",
                               validatorsDir,
                               remoteSignersUrls,
                               threshold)

    deposits.add prepareDeposit(
      cfg, withdrawalPubKey, derivedKey, signingPubKey)

  ok deposits

proc saveWallet*(wallet: Wallet, outWalletPath: string): Result[void, string] =
  let walletDir = splitFile(outWalletPath).dir
  var encodedWallet: string
  try:
    encodedWallet = Json.encode(wallet, pretty = true)
  except SerializationError:
    return err("Could not serialize wallet")

  ? secureCreatePath(walletDir).mapErr(proc(e: auto): string =
    "Could not create wallet directory [" & walletDir & "]: " & $e)

  ? secureWriteFile(outWalletPath, encodedWallet).mapErr(proc(e: auto): string =
    "Could not write wallet to file [" & outWalletPath & "]: " & $e)

  ok()

proc saveWallet*(wallet: WalletPathPair): Result[void, string] =
  saveWallet(wallet.wallet, wallet.path)

proc readPasswordInput(prompt: string, password: var string): bool =
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

proc importKeystoresFromDir*(rng: var BrHmacDrbgContext,
                             importedDir, validatorsDir, secretsDir: string) =
  var password: string  # TODO consider using a SecretString type
  defer: burnMem(password)

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
          Json.loadFile(file, Keystore)
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
            var password = KeystorePass.init ncrutils.toHex(getRandomBytes(rng, 32))
            defer: burnMem(password)
            let status = saveKeystore(rng, validatorsDir, secretsDir,
                                      privKey.value, pubkey,
                                      keystore.path, password.str)
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
              echo msg % [file]
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

proc pickPasswordAndSaveWallet(rng: var BrHmacDrbgContext,
                               config: BeaconNodeConf,
                               seed: KeySeed): Result[WalletPathPair, string] =
  echoP "When you perform operations with your wallet such as withdrawals " &
        "and additional deposits, you'll be asked to enter a signing " &
        "password. Please note that this password is local to the current " &
        "machine and you can change it at any time."
  echo ""

  var password =
    block:
      let prompt = "Please enter a password: "
      let confirm = "Please repeat the password: "
      ? keyboardCreatePassword(prompt, confirm).mapErr(proc(e: auto): string = $e)
  defer: burnMem(password)

  var name: WalletName
  let outWalletName = config.outWalletName
  if outWalletName.isSome:
    name = outWalletName.get
  else:
    echoP "For your convenience, the wallet can be identified with a name " &
          "of your choice. Please enter a wallet name below or press ENTER " &
          "to continue with a machine-generated name."
    echo ""

    while true:
      var enteredName = ask "Wallet name"
      if enteredName.len > 0:
        name =
          try:
            WalletName.parseCmdArg(enteredName)
          except CatchableError as err:
            echo err.msg & ". Please try again."
            continue
      break

  let nextAccount =
    if config.cmd == wallets and config.walletsCmd == WalletsCmd.restore:
      config.restoredDepositsCount
    else:
      none Natural

  let wallet = createWallet(kdfPbkdf2, rng, seed,
                            name = name,
                            nextAccount = nextAccount,
                            password = KeystorePass.init password)

  let outWalletFileFlag = config.outWalletFile
  let outWalletFile =
    if outWalletFileFlag.isSome:
      string outWalletFileFlag.get
    else:
      config.walletsDir / addFileExt(string wallet.name, "json")

  let status = saveWallet(wallet, outWalletFile)
  if status.isErr:
    return err("failure to create wallet file due to " & status.error)

  echo "\nWallet file successfully written to \"", outWalletFile, "\""
  return ok WalletPathPair(wallet: wallet, path: outWalletFile)

when defined(windows):
  proc clearScreen =
    discard execShellCmd("cls")
else:
  template clearScreen =
    echo "\e[1;1H\e[2J\e[3J"

proc createWalletInteractively*(
    rng: var BrHmacDrbgContext,
    config: BeaconNodeConf): Result[CreatedWallet, string] =

  if config.nonInteractive:
    return err "not running in interactive mode"

  echoP "The generated wallet is uniquely identified by a seed phrase " &
        "consisting of 24 words. In case you lose your wallet and you " &
        "need to restore it on a different machine, you can use the " &
        "seed phrase to re-generate your signing and withdrawal keys."
  echoP "The seed phrase should be kept secret in a safe location as if " &
        "you are protecting a sensitive password. It can be used to withdraw " &
        "funds from your wallet."
  echoP "We will display the seed phrase on the next screen. Please make sure " &
        "you are in a safe environment and there are no cameras or potentially " &
        "unwanted eye witnesses around you. Please prepare everything necessary " &
        "to copy the seed phrase to a safe location and type 'continue' in " &
        "the prompt below to proceed to the next screen or 'q' to exit now."
  echo ""

  while true:
    let answer = ask "Action"
    if answer.len > 0 and answer[0] == 'q': quit 1
    if answer == "continue": break
    echoP "To proceed to your seed phrase, please type 'continue' (without the quotes). " &
          "Type 'q' to exit now."
    echo ""

  var mnemonic = generateMnemonic(rng)
  defer: burnMem(mnemonic)

  try:
    echoP "Your seed phrase is:"
    setStyleNoError({styleBright})
    setForegroundColorNoError fgCyan
    echoP $mnemonic
    resetAttributesNoError()
  except IOError, ValueError:
    return err "failure to write to the standard output"

  echoP "Press any key to continue."
  try:
    discard getch()
  except IOError as err:
    fatal "Failed to read a key from stdin", err = err.msg
    quit 1

  clearScreen()

  echoP "To confirm that you've saved the seed phrase, please enter the " &
        "first and the last three words of it. In case you've saved the " &
        "seek phrase in your clipboard, we strongly advice clearing the " &
        "clipboard now."
  echo ""

  for i in countdown(2, 0):
    let answer = ask "Answer"
    let parts = answer.split(' ', maxsplit = 1)
    if parts.len == 2:
      if count(parts[1], ' ') == 2 and
         mnemonic.string.startsWith(parts[0]) and
         mnemonic.string.endsWith(parts[1]):
        break
    else:
      doAssert parts.len == 1

    if i > 0:
      echo "\nYour answer was not correct. You have ", i, " more attempts"
      echoP "Please enter 4 words separated with a single space " &
            "(the first word from the seed phrase, followed by the last 3)"
      echo ""
    else:
      quit 1

  clearScreen()

  var mnenomicPassword = KeystorePass.init ""
  defer: burnMem(mnenomicPassword)

  echoP "The recovery of your wallet can be additionally protected by a" &
        "recovery password. Since the seed phrase itself can be considered " &
        "a password, setting such an additional password is optional. " &
        "To ensure the strongest possible security, we recommend writing " &
        "down your seed phrase and remembering your recovery password. " &
        "If you don't want to set a recovery password, just press ENTER."

  var recoveryPassword = keyboardCreatePassword(
    "Recovery password: ", "Confirm password: ", allowEmpty = true)
  defer:
    if recoveryPassword.isOk:
      burnMem(recoveryPassword.get)

  if recoveryPassword.isErr:
    fatal "Failed to read password from stdin: "
    quit 1

  var keystorePass = KeystorePass.init recoveryPassword.get
  defer: burnMem(keystorePass)

  var seed = getSeed(mnemonic, keystorePass)
  defer: burnMem(seed)

  let walletPath = ? pickPasswordAndSaveWallet(rng, config, seed)
  return ok CreatedWallet(walletPath: walletPath, seed: seed)

proc restoreWalletInteractively*(rng: var BrHmacDrbgContext,
                                 config: BeaconNodeConf) =
  var
    enteredMnemonic: string
    validatedMnemonic: Mnemonic

  defer:
    burnMem enteredMnemonic
    burnMem validatedMnemonic

  echo "To restore your wallet, please enter your backed-up seed phrase."
  while true:
    if not readPasswordInput("Seedphrase: ", enteredMnemonic):
      fatal "failure to read password from stdin"
      quit 1

    if validateMnemonic(enteredMnemonic, validatedMnemonic):
      break
    else:
      echo "The entered mnemonic was not valid. Please try again."

  echoP "If your seed phrase was protected with a recovery password, " &
        "please enter it below. Please ENTER to attempt to restore " &
        "the wallet without a recovery password."

  var recoveryPassword = keyboardCreatePassword(
    "Recovery password: ", "Confirm password: ", allowEmpty = true)
  defer:
    if recoveryPassword.isOk:
      burnMem(recoveryPassword.get)

  if recoveryPassword.isErr:
    fatal "Failed to read password from stdin"
    quit 1

  var keystorePass = KeystorePass.init recoveryPassword.get
  defer: burnMem(keystorePass)

  var seed = getSeed(validatedMnemonic, keystorePass)
  defer: burnMem(seed)

  discard pickPasswordAndSaveWallet(rng, config, seed)

proc unlockWalletInteractively*(wallet: Wallet): Result[KeySeed, string] =
  echo "Please enter the password for unlocking the wallet"

  let res = keyboardGetPassword[KeySeed]("Password: ", 3,
    proc (password: string): KsResult[KeySeed] =
      var secret: seq[byte]
      defer: burnMem(secret)
      let status = decryptCryptoField(wallet.crypto, KeystorePass.init password, secret)
      case status
      of DecryptionStatus.Success:
        ok(KeySeed secret)
      else:
        # TODO Handle InvalidKeystore in a special way here
        let failed = "Unlocking of the wallet failed. Please try again"
        echo failed
        err(failed)
  )

  if res.isOk():
    ok(res.get())
  else:
    err "Unlocking of the wallet failed."

proc loadWallet*(fileName: string): Result[Wallet, string] =
  try:
    ok Json.loadFile(fileName, Wallet)
  except SerializationError as err:
    err "Invalid wallet syntax: " & err.formatMsg(fileName)
  except IOError as err:
    err "Error accessing wallet file \"" & fileName & "\": " & err.msg

proc findWallet*(config: BeaconNodeConf,
                 name: WalletName): Result[Option[WalletPathPair], string] =
  var walletFiles = newSeq[string]()
  try:
    for kind, walletFile in walkDir(config.walletsDir):
      if kind != pcFile: continue
      let walletId = splitFile(walletFile).name
      if cmpIgnoreCase(walletId, name.string) == 0:
        let wallet = ? loadWallet(walletFile)
        return ok some WalletPathPair(wallet: wallet, path: walletFile)
      walletFiles.add walletFile
  except OSError as err:
    return err("Error accessing the wallets directory \"" &
                config.walletsDir & "\": " & err.msg)

  for walletFile in walletFiles:
    let wallet = ? loadWallet(walletFile)
    if cmpIgnoreCase(wallet.name.string, name.string) == 0 or
       cmpIgnoreCase(wallet.uuid.string, name.string) == 0:
      return ok some WalletPathPair(wallet: wallet, path: walletFile)

  return ok none(WalletPathPair)

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
