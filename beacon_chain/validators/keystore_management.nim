import
  std/os,
  chronicles, chronos, json_serialization,
  serialization, blscurve, eth/common/eth_types, confutils,
  ".."/spec/[eth2_merkleization, keystore, crypto],
  ".."/spec/datatypes/base,
  stew/io2, libp2p/crypto/crypto as lcrypto,
  ".."/[conf, filepath, beacon_clock],
  ./validator_pool

export
  keystore, validator_pool, crypto

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

  error "Unable to load validator key store. Please ensure matching " &
        "passphrase exists in the secrets dir", key_path = keystorePath,
        key_name = keyName, validatorsDir, secretsDir = secretsDir
  return Opt.none(KeystoreData)

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
