{.used.}

import
  std/[os, options, json, typetraits],
  unittest2, chronos, chronicles, stint, json_serialization,
  blscurve, eth/keys, nimcrypto/utils,
  libp2p/crypto/crypto as lcrypto,
  stew/[io2, byteutils],
  ../beacon_chain/filepath,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/spec/eth2_merkleization,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/[crypto, keystore],
  ../beacon_chain/validators/keystore_management,
  ./testutil

const
  simulationDepositsCount = 2
  testDataDir = "./test_keystore_management"
  testValidatorsDir = testDataDir / "validators"
  testSecretsDir = testDataDir / "secrets"

proc directoryItemsCount(dir: string): int {.raises: [OSError].} =
  for el in walkDir(dir):
    result += 1

proc isEmptyDir(dir: string): bool =
  directoryItemsCount(dir) == 0

proc validatorPubKeysInDir(dir: string): seq[string] =
  for kind, file in walkDir(dir):
    if kind == pcDir:
      result.add(splitFile(file).name)

proc contentEquals(filePath, expectedContent: string): bool =
  var file: File

  discard open(file, filePath)
  defer: close(file)

  expectedContent == readAll(file)

let
  rng = keys.newRng()
  mnemonic = generateMnemonic(rng[])
  seed = getSeed(mnemonic, KeyStorePass.init "")
  cfg = defaultRuntimeConfig
  validatorDirRes = secureCreatePath(testValidatorsDir)

if validatorDirRes.isErr():
  warn "Could not create validators folder",
        path = testValidatorsDir, err = ioErrorMsg(validatorDirRes.error)

let secretDirRes = secureCreatePath(testSecretsDir)
if secretDirRes.isErr():
  warn "Could not create secrets folder",
        path = testSecretsDir, err = ioErrorMsg(secretDirRes.error)

let deposits = generateDeposits(
  cfg,
  rng[],
  seed,
  0, simulationDepositsCount,
  testValidatorsDir,
  testSecretsDir)

if deposits.isErr:
  fatal "Failed to generate deposits", err = deposits.error
  quit 1

let validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

suite "removeValidatorFiles":
  test "Remove validator files":
    let
      validatorsCountBefore = directoryItemsCount(testValidatorsDir)
      secretsCountBefore = directoryItemsCount(testSecretsDir)
      firstValidator = validatorPubKeys[0]
      removeValidatorFilesRes = removeValidatorFiles(
        testValidatorsDir, testSecretsDir, firstValidator, KeystoreKind.Local)
      validatorsCountAfter = directoryItemsCount(testValidatorsDir)
      secretsCountAfter = directoryItemsCount(testSecretsDir)

    check:
      removeValidatorFilesRes.isOk
      removeValidatorFilesRes.value == RemoveValidatorStatus.deleted
      validatorsCountBefore - 1 == validatorsCountAfter
      not fileExists(testValidatorsDir / firstValidator / KeystoreFileName)
      not fileExists(testValidatorsDir / firstValidator)
      secretsCountBefore - 1 == secretsCountAfter
      not fileExists(testSecretsDir / firstValidator)

  test "Remove nonexistent validator":
    let
      nonexistentValidator =
        "0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
      res = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                 nonexistentValidator, KeystoreKind.Local)

    check(res.isOk and res.value == RemoveValidatorStatus.notFound)

  test "Remove validator files twice":
    let
      secondValidator = validatorPubKeys[1]
      res1 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  secondValidator, KeystoreKind.Local)
      res2 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  secondValidator, KeystoreKind.Local)

    check:
      not fileExists(testValidatorsDir / secondValidator)
      not fileExists(testSecretsDir / secondValidator)
      res1.isOk and res1.value() == RemoveValidatorStatus.deleted
      res2.isOk and res2.value() == RemoveValidatorStatus.notFound

  os.removeDir testValidatorsDir
  os.removeDir testSecretsDir

suite "createValidatorFiles":
  setup:
    const
      password = string.fromBytes hexToSeqByte("7465737470617373776f7264f09f9491")
      secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
      secretNetBytes = hexToSeqByte "08021220fe442379443d6e2d7d75d3a58f96fbb35f0a9c7217796825fc9040e3b89c5736"
      salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
      iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"

    let
      secret = ValidatorPrivKey.fromRaw(secretBytes).get

      keystore = createKeystore(
        kdfPbkdf2, rng[], secret,
        KeystorePass.init password,
        salt=salt, iv=iv,
        description = "This is a test keystore that uses PBKDF2 to secure the secret.",
        path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))
      keystoreJsonContents = Json.encode(keystore)

      hexEncodedPubkey =  "0x" & keystore.pubkey.toHex()
      keystoreDir = testValidatorsDir / hexEncodedPubkey
      secretFile = testSecretsDir / hexEncodedPubkey
      keystoreFile = testValidatorsDir / hexEncodedPubkey / KeystoreFileName

  teardown:
    os.removeDir testValidatorsDir
    os.removeDir testSecretsDir

  test "Add keystore files":
    let
      res = createValidatorFiles(testSecretsDir, testValidatorsDir,
                                 keystoreDir,
                                 secretFile, password,
                                 keystoreFile, keystoreJsonContents)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res.isOk

      validatorsCount == 1
      secretsCount == 1

      dirExists(testValidatorsDir / hexEncodedPubkey)
      fileExists(testSecretsDir / hexEncodedPubkey)

      secretFile.contentEquals password
      keystoreFile.contentEquals keystoreJsonContents

  test "Add keystore files twice":
    let
      res1 = createValidatorFiles(testSecretsDir, testValidatorsDir,
                                  keystoreDir,
                                  secretFile, password,
                                  keystoreFile, keystoreJsonContents)

      res2 = createValidatorFiles(testSecretsDir, testValidatorsDir,
                                  keystoreDir,
                                  secretFile, password,
                                  keystoreFile, keystoreJsonContents)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)
      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk # The second call should just overwrite the results of the first

      validatorsCount == 1
      secretsCount == 1

      dirExists(testValidatorsDir / hexEncodedPubkey)
      fileExists(testSecretsDir / hexEncodedPubkey)
      secretFile.contentEquals password
      keystoreFile.contentEquals keystoreJsonContents

  # TODO The following tests are disabled on Windows because the io2 module
  # doesn't implement the permission/mode parameter at the moment:
  when not defined(windows):
    test "`createValidatorFiles` with `secretsDir` without permissions":
      # Creating `secrets` dir with `UserRead` permissions before
      # calling `createValidatorFiles` which should result in problem
      # with creating a secret file inside the dir:
      let
        secretsDirNoPermissions = createPath(testSecretsDir, 0o400)
        res = createValidatorFiles(testSecretsDir, testValidatorsDir,
                                   keystoreDir,
                                   secretFile, password,
                                   keystoreFile, keystoreJsonContents)
      check:
        res.isErr and res.error.kind == FailedToCreateSecretFile

        # The secrets dir was pre-existing, so it should be preserved and
        # it should remain empty:
        dirExists(testSecretsDir)
        testSecretsDir.isEmptyDir

        # The creation of the validators dir should be rolled-back
        not dirExists(testValidatorsDir)

    test "`createValidatorFiles` with `validatorsDir` without permissions":
      # Creating `validators` dir with `UserRead` permissions before
      # calling `createValidatorFiles` which should result in problems
      # creating `keystoreDir` inside the dir.
      let
        validatorsDirNoPermissions = createPath(testValidatorsDir, 0o400)
        res = createValidatorFiles(testSecretsDir, testValidatorsDir,
                                   keystoreDir,
                                   secretFile, password,
                                   keystoreFile, keystoreJsonContents)
      check:
        res.isErr and res.error.kind == FailedToCreateKeystoreDir

        # The creation of the secrets dir should be rolled-back
        not dirExists(testSecretsDir)

        # The validators dir was pre-existing, so it should be preserved and
        # it should remain empty:
        dirExists(testValidatorsDir)
        testValidatorsDir.isEmptyDir

    test "`createValidatorFiles` with `keystoreDir` without permissions":
      # Creating `keystore` dir with `UserRead` permissions before
      # calling `createValidatorFiles` which should result in problems
      # creating keystore file inside this dir:
      let
        validatorsDir = createPath(testValidatorsDir, 0o700)
        keystoreDirNoPermissions = createPath(keystoreDir, 0o400)
        res = createValidatorFiles(testSecretsDir, testValidatorsDir,
                                   keystoreDir,
                                   secretFile, password,
                                   keystoreFile, keystoreJsonContents)
      check:
        res.isErr and res.error.kind == FailedToCreateKeystoreFile

        not dirExists(testSecretsDir)

        dirExists(testValidatorsDir)
        not fileExists(testValidatorsDir / hexEncodedPubkey)
        testValidatorsDir.isEmptyDir

    test "`createValidatorFiles` with already existing dirs and any error":
      # Generate deposits so we have files and dirs already existing
      # before testing `createValidatorFiles` failure
      let
        deposits = generateDeposits(
          cfg,
          rng[],
          seed,
          0, simulationDepositsCount,
          testValidatorsDir,
          testSecretsDir)

        validatorsCountBefore = directoryItemsCount(testValidatorsDir)
        secretsCountBefore = directoryItemsCount(testSecretsDir)

        # Creating `keystore` dir with `UserRead` permissions before calling `createValidatorFiles`
        # which will result in error
        keystoreDirNoPermissions = createPath(keystoreDir, 0o400)

        res = createValidatorFiles(testSecretsDir, testValidatorsDir,
                                   keystoreDir,
                                   secretFile, password,
                                   keystoreFile, keystoreJsonContents)

        validatorsCountAfter = directoryItemsCount(testValidatorsDir)
        secretsCountAfter = directoryItemsCount(testSecretsDir)

      check:
        res.isErr

        # `secrets` & `validators` should be removed during the roll-back:
        dirExists(testSecretsDir)
        dirExists(testValidatorsDir)

        # The number of directies should not have changed after the failure:
        validatorsCountBefore == validatorsCountAfter
        secretsCountBefore == secretsCountAfter

  os.removeDir testDataDir
