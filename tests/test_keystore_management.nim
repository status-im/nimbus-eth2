# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[os, options, json, typetraits, uri, algorithm],
  unittest2, chronos, chronicles, stint, json_serialization,
  blscurve,
  libp2p/crypto/crypto as lcrypto,
  stew/[io2, byteutils],
  ../beacon_chain/filepath,
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
  rng = HmacDrbgContext.new()
  mnemonic = generateMnemonic(rng[])
  seed = getSeed(mnemonic, KeystorePass.init "")
  cfg = defaultRuntimeConfig
  validatorDirRes = secureCreatePath(testValidatorsDir)

proc namesEqual(a, b: openArray[string]): bool =
  sorted(a) == sorted(b)

when not defined(windows):
  proc isEmptyDir(dir: string): bool =
    directoryItemsCount(dir) == 0

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

const
  MultiplePassword = string.fromBytes(
    hexToSeqByte("7465737470617373776f7264f09f9491"))
  MultipleSalt = hexToSeqByte(
    "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
  MultipleIv = hexToSeqByte("264daa3f303d7259501c93d997d84fe6")
  MultipleRemoteUri = HttpHostUri(parseUri("https://127.0.0.1/eth/web3signer"))

  MultiplePrivateKeys = [
    "3b89cdf5c62b423dab64dd69476c6c74bdbccc684abc89f3b392ac1f679e06c3",
    "5140621611300ed419f901d8c56baf32d89d876272bbb3ab16e1c9f0884487d4"
  ]

var
  MultipleKeystoreNames: seq[string]
  MultipleSigningKeys: seq[ValidatorPrivKey]
  MultipleLocalKeystores: seq[Keystore]
  MultipleLocalKeystoreJsons: seq[string]
  MultipleRemoteKeystores: seq[RemoteKeystore]
  MultipleRemoteKeystoreJsons: seq[string]

for key in MultiplePrivateKeys:
  let
    nsecret = ValidatorPrivKey.fromRaw(hexToSeqByte(key)).get()
    npubkey = nsecret.toPubKey().toPubKey()
    keystoreName = "0x" & npubkey.toHex()

    localKeystore = createKeystore(
      kdfPbkdf2, rng[], nsecret,
      KeystorePass.init MultiplePassword,
      salt = MultipleSalt, iv = MultipleIv,
      description = "This is a test keystore.",
      path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))
    localKeystoreJson = Json.encode(localKeystore)

    remoteKeystore = createRemoteKeystore(npubkey, MultipleRemoteUri)
    remoteKeystoreJson = Json.encode(remoteKeystore)

  MultipleSigningKeys.add(nsecret)
  MultipleKeystoreNames.add(keystoreName)
  MultipleLocalKeystores.add(localKeystore)
  MultipleLocalKeystoreJsons.add(localKeystoreJson)
  MultipleRemoteKeystores.add(remoteKeystore)
  MultipleRemoteKeystoreJsons.add(remoteKeystoreJson)

suite "removeValidatorFiles()":
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

suite "removeValidatorFiles() multiple keystore types":
  setup:
    let
      curKeystoreDir0 {.used.} = testValidatorsDir / MultipleKeystoreNames[0]
      curSecretsFile0 {.used.} = testSecretsDir / MultipleKeystoreNames[0]
      remoteKeystoreFile0 {.used.} = curKeystoreDir0 / RemoteKeystoreFileName
      localKeystoreFile0 {.used.} = curKeystoreDir0 / KeystoreFileName
      curSigningKey0 {.used.} = MultipleSigningKeys[0]
      curCookedKey0 {.used.} = curSigningKey0.toPubKey()
      curPublicKey0 {.used.} = curCookedKey0.toPubKey()

      curKeystoreDir1 {.used.} = testValidatorsDir / MultipleKeystoreNames[1]
      curSecretsFile1 {.used.} = testSecretsDir / MultipleKeystoreNames[1]
      remoteKeystoreFile1 {.used.} = curKeystoreDir1 / RemoteKeystoreFileName
      localKeystoreFile1 {.used.} = curKeystoreDir1 / KeystoreFileName
      curSigningKey1 {.used.} = MultipleSigningKeys[1]
      curCookedKey1 {.used.} = curSigningKey1.toPubKey()
      curPublicKey1 {.used.} = curCookedKey1.toPubKey()

      curSigningPath {.used.} =
        validateKeyPath("m/12381/60/0/0").expect("Valid Keypath")

  teardown:
    os.removeDir testValidatorsDir
    os.removeDir testSecretsDir

  test "Remove [LOCAL] when [LOCAL] is present":
    let
      res1 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      validatorsCount1 = directoryItemsCount(testValidatorsDir)
      secretsCount1 = directoryItemsCount(testSecretsDir)
      validatorPubKeys1 = validatorPubKeysInDir(testValidatorsDir)

      res2 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  MultipleKeystoreNames[0], KeystoreKind.Local)

      validatorsCount2 = directoryItemsCount(testValidatorsDir)
      secretsCount2 = directoryItemsCount(testSecretsDir)
      validatorPubKeys2 = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk
      res2.value == RemoveValidatorStatus.deleted

      validatorsCount1 == 1
      secretsCount1 == 1
      validatorsCount2 == 0
      secretsCount2 == 0

      not(dirExists(curKeystoreDir0))
      not(fileExists(remoteKeystoreFile0))
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      namesEqual(validatorPubKeys1, [MultipleKeystoreNames[0]])
      namesEqual(validatorPubKeys2, [])

  test "Remove [LOCAL] when [LOCAL] is missing":
    let
      res1 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      validatorsCount1 = directoryItemsCount(testValidatorsDir)
      secretsCount1 = directoryItemsCount(testSecretsDir)
      validatorPubKeys1 = validatorPubKeysInDir(testValidatorsDir)

      res2 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  MultipleKeystoreNames[1], KeystoreKind.Local)

      validatorsCount2 = directoryItemsCount(testValidatorsDir)
      secretsCount2 = directoryItemsCount(testSecretsDir)
      validatorPubKeys2 = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk
      res2.value == RemoveValidatorStatus.notFound

      validatorsCount1 == 1
      secretsCount1 == 1
      validatorsCount2 == 1
      secretsCount2 == 1

      dirExists(curKeystoreDir0)
      not(fileExists(remoteKeystoreFile0))
      fileExists(localKeystoreFile0)
      fileExists(curSecretsFile0)

      namesEqual(validatorPubKeys1, [MultipleKeystoreNames[0]])
      namesEqual(validatorPubKeys2, [MultipleKeystoreNames[0]])

  test "Remove [REMOTE] when [REMOTE] is present":
    let
      res1 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)

      validatorsCount1 = directoryItemsCount(testValidatorsDir)
      secretsCount1 = directoryItemsCount(testSecretsDir)
      validatorPubKeys1 = validatorPubKeysInDir(testValidatorsDir)

      res2 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  MultipleKeystoreNames[0], KeystoreKind.Remote)

      validatorsCount2 = directoryItemsCount(testValidatorsDir)
      secretsCount2 = directoryItemsCount(testSecretsDir)
      validatorPubKeys2 = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk
      res2.value == RemoveValidatorStatus.deleted

      validatorsCount1 == 1
      secretsCount1 == 0
      validatorsCount2 == 0
      secretsCount2 == 0

      not(dirExists(curKeystoreDir0))
      not(fileExists(remoteKeystoreFile0))
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      namesEqual(validatorPubKeys1, [MultipleKeystoreNames[0]])
      namesEqual(validatorPubKeys2, [])

  test "Remove [REMOTE] when [REMOTE] is missing":
    let
      res1 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)

      validatorsCount1 = directoryItemsCount(testValidatorsDir)
      secretsCount1 = directoryItemsCount(testSecretsDir)
      validatorPubKeys1 = validatorPubKeysInDir(testValidatorsDir)

      res2 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  MultipleKeystoreNames[1], KeystoreKind.Remote)

      validatorsCount2 = directoryItemsCount(testValidatorsDir)
      secretsCount2 = directoryItemsCount(testSecretsDir)
      validatorPubKeys2 = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk
      res2.value == RemoveValidatorStatus.notFound

      validatorsCount1 == 1
      secretsCount1 == 0
      validatorsCount2 == 1
      secretsCount2 == 0

      dirExists(curKeystoreDir0)
      fileExists(remoteKeystoreFile0)
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      namesEqual(validatorPubKeys1, [MultipleKeystoreNames[0]])
      namesEqual(validatorPubKeys2, [MultipleKeystoreNames[0]])

  test "Remove [LOCAL] when [REMOTE] is present":
    let
      res1 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)

      validatorsCount1 = directoryItemsCount(testValidatorsDir)
      secretsCount1 = directoryItemsCount(testSecretsDir)
      validatorPubKeys1 = validatorPubKeysInDir(testValidatorsDir)

      res2 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  MultipleKeystoreNames[0], KeystoreKind.Local)

      validatorsCount2 = directoryItemsCount(testValidatorsDir)
      secretsCount2 = directoryItemsCount(testSecretsDir)
      validatorPubKeys2 = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk
      res2.value == RemoveValidatorStatus.notFound

      validatorsCount1 == 1
      secretsCount1 == 0
      validatorsCount2 == 1
      secretsCount2 == 0

      dirExists(curKeystoreDir0)
      fileExists(remoteKeystoreFile0)
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      namesEqual(validatorPubKeys1, [MultipleKeystoreNames[0]])
      namesEqual(validatorPubKeys2, [MultipleKeystoreNames[0]])

  test "Remove [REMOTE] when [LOCAL] is present":
    let
      res1 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      validatorsCount1 = directoryItemsCount(testValidatorsDir)
      secretsCount1 = directoryItemsCount(testSecretsDir)
      validatorPubKeys1 = validatorPubKeysInDir(testValidatorsDir)

      res2 = removeValidatorFiles(testValidatorsDir, testSecretsDir,
                                  MultipleKeystoreNames[0], KeystoreKind.Remote)

      validatorsCount2 = directoryItemsCount(testValidatorsDir)
      secretsCount2 = directoryItemsCount(testSecretsDir)
      validatorPubKeys2 = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk
      res2.value == RemoveValidatorStatus.notFound

      validatorsCount1 == 1
      secretsCount1 == 1
      validatorsCount2 == 1
      secretsCount2 == 1

      dirExists(curKeystoreDir0)
      not(fileExists(remoteKeystoreFile0))
      fileExists(localKeystoreFile0)
      fileExists(curSecretsFile0)

      namesEqual(validatorPubKeys1, [MultipleKeystoreNames[0]])
      namesEqual(validatorPubKeys2, [MultipleKeystoreNames[0]])

  os.removeDir testValidatorsDir
  os.removeDir testSecretsDir

suite "createValidatorFiles()":
  setup:
    const
      password = string.fromBytes hexToSeqByte("7465737470617373776f7264f09f9491")
      secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
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
      keystoreJsonContents {.used.} = Json.encode(keystore)

      hexEncodedPubkey =  "0x" & keystore.pubkey.toHex()
      keystoreDir {.used.} = testValidatorsDir / hexEncodedPubkey
      secretFile {.used.} = testSecretsDir / hexEncodedPubkey
      keystoreFile {.used.} = testValidatorsDir / hexEncodedPubkey /
                              KeystoreFileName

  teardown:
    os.removeDir testValidatorsDir
    os.removeDir testSecretsDir

  test "Add keystore files [LOCAL]":
    let
      res = createLocalValidatorFiles(testSecretsDir, testValidatorsDir,
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

      namesEqual(validatorPubKeys, [hexEncodedPubkey])

  test "Add keystore files twice [LOCAL]":
    let
      res1 = createLocalValidatorFiles(testSecretsDir, testValidatorsDir,
                                       keystoreDir,
                                       secretFile, password,
                                       keystoreFile, keystoreJsonContents)

      res2 = createLocalValidatorFiles(testSecretsDir, testValidatorsDir,
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

      namesEqual(validatorPubKeys, [hexEncodedPubkey])

  test "Add keystore files [REMOTE]":
    let
      curKeystoreDir = testValidatorsDir / MultipleKeystoreNames[0]
      curSecretsFile = testSecretsDir / MultipleKeystoreNames[0]
      remoteKeystoreFile = curKeystoreDir / RemoteKeystoreFileName
      localKeystoreFile = curKeystoreDir / KeystoreFileName

      res = createRemoteValidatorFiles(testValidatorsDir, curKeystoreDir,
                                       remoteKeystoreFile,
                                       MultipleRemoteKeystoreJsons[0])

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res.isOk

      validatorsCount == 1
      secretsCount == 0

      dirExists(curKeystoreDir)
      fileExists(remoteKeystoreFile)
      not(fileExists(localKeystoreFile))
      not(fileExists(curSecretsFile))

      remoteKeystoreFile.contentEquals MultipleRemoteKeystoreJsons[0]


      namesEqual(validatorPubKeys, [MultipleKeystoreNames[0]])

  test "Add keystore files twice [REMOTE]":
    let
      curKeystoreDir = testValidatorsDir / MultipleKeystoreNames[0]
      curSecretsFile = testSecretsDir / MultipleKeystoreNames[0]
      remoteKeystoreFile = curKeystoreDir / RemoteKeystoreFileName
      localKeystoreFile = curKeystoreDir / KeystoreFileName

      res1 = createRemoteValidatorFiles(testValidatorsDir, curKeystoreDir,
                                        remoteKeystoreFile,
                                        MultipleRemoteKeystoreJsons[0])

      res2 = createRemoteValidatorFiles(testValidatorsDir, curKeystoreDir,
                                        remoteKeystoreFile,
                                        MultipleRemoteKeystoreJsons[0])

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk # The second call should just overwrite the results of the first

      validatorsCount == 1
      secretsCount == 0

      dirExists(curKeystoreDir)
      fileExists(remoteKeystoreFile)
      not(fileExists(localKeystoreFile))
      not(fileExists(curSecretsFile))

      remoteKeystoreFile.contentEquals MultipleRemoteKeystoreJsons[0]

      namesEqual(validatorPubKeys, [MultipleKeystoreNames[0]])

  # TODO The following tests are disabled on Windows because the io2 module
  # doesn't implement the permission/mode parameter at the moment:
  when not defined(windows):
    test "`createLocalValidatorFiles` with `secretsDir` without permissions":
      # Creating `secrets` dir with `UserRead` permissions before
      # calling `createValidatorFiles` which should result in problem
      # with creating a secret file inside the dir:
      let
        secretsDirNoPermissions = createPath(testSecretsDir, 0o400)
        res = createLocalValidatorFiles(testSecretsDir, testValidatorsDir,
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

    test "`createLocalValidatorFiles` with `validatorsDir` without permissions":
      # Creating `validators` dir with `UserRead` permissions before
      # calling `createValidatorFiles` which should result in problems
      # creating `keystoreDir` inside the dir.
      let
        validatorsDirNoPermissions = createPath(testValidatorsDir, 0o400)
        res = createLocalValidatorFiles(testSecretsDir, testValidatorsDir,
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

    test "`createLocalValidatorFiles` with `keystoreDir` without permissions":
      # Creating `keystore` dir with `UserRead` permissions before
      # calling `createValidatorFiles` which should result in problems
      # creating keystore file inside this dir:
      let
        validatorsDir = createPath(testValidatorsDir, 0o700)
        keystoreDirNoPermissions = createPath(keystoreDir, 0o400)
        res = createLocalValidatorFiles(testSecretsDir, testValidatorsDir,
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

        # Creating `keystore` dir with `UserRead` permissions before calling
        # `createValidatorFiles` which will result in error
        keystoreDirNoPermissions = createPath(keystoreDir, 0o400)

        res = createLocalValidatorFiles(testSecretsDir, testValidatorsDir,
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

suite "saveKeystore()":
  setup:
    let
      curKeystoreDir0 = testValidatorsDir / MultipleKeystoreNames[0]
      curSecretsFile0 = testSecretsDir / MultipleKeystoreNames[0]
      remoteKeystoreFile0 = curKeystoreDir0 / RemoteKeystoreFileName
      localKeystoreFile0 = curKeystoreDir0 / KeystoreFileName
      curSigningKey0 = MultipleSigningKeys[0]
      curCookedKey0 = curSigningKey0.toPubKey()
      curPublicKey0 {.used.} = curCookedKey0.toPubKey()

      curKeystoreDir1 = testValidatorsDir / MultipleKeystoreNames[1]
      curSecretsFile1 {.used.} = testSecretsDir / MultipleKeystoreNames[1]
      remoteKeystoreFile1 {.used.} = curKeystoreDir1 / RemoteKeystoreFileName
      localKeystoreFile1 {.used.} = curKeystoreDir1 / KeystoreFileName
      curSigningKey1 = MultipleSigningKeys[1]
      curCookedKey1 = curSigningKey1.toPubKey()
      curPublicKey1 {.used.} = curCookedKey1.toPubKey()

      curSigningPath {.used.} =
        validateKeyPath("m/12381/60/0/0").expect("Valid Keypath")

  teardown:
    os.removeDir testValidatorsDir
    os.removeDir testSecretsDir

  test "Save [LOCAL] keystore after [LOCAL] keystore with same id":
    let
      res1 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      res2 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isErr
      res2.error().kind == DuplicateKeystoreDir

      validatorsCount == 1
      secretsCount == 1

      dirExists(curKeystoreDir0)
      not(fileExists(remoteKeystoreFile0))
      fileExists(localKeystoreFile0)
      fileExists(curSecretsFile0)

      namesEqual(validatorPubKeys, [MultipleKeystoreNames[0]])

  test "Save [REMOTE] keystore after [REMOTE] keystore with same id":
    let
      res1 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)
      res2 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isErr
      res2.error().kind == DuplicateKeystoreDir

      validatorsCount == 1
      secretsCount == 0

      dirExists(curKeystoreDir0)
      fileExists(remoteKeystoreFile0)
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      namesEqual(validatorPubKeys, [MultipleKeystoreNames[0]])

  test "Save [REMOTE] keystore after [LOCAL] keystore with same id":
    let
      res1 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      res2 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isErr
      res2.error().kind == DuplicateKeystoreDir

      validatorsCount == 1
      secretsCount == 1

      dirExists(curKeystoreDir0)
      not(fileExists(remoteKeystoreFile0))
      fileExists(localKeystoreFile0)
      fileExists(curSecretsFile0)

      namesEqual(validatorPubKeys, [MultipleKeystoreNames[0]])

  test "Save [LOCAL] keystore after [REMOTE] keystore with same id":
    let
      res1 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)
      res2 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isErr
      res2.error().kind == DuplicateKeystoreDir

      validatorsCount == 1
      secretsCount == 0

      dirExists(curKeystoreDir0)
      fileExists(remoteKeystoreFile0)
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      namesEqual(validatorPubKeys, [MultipleKeystoreNames[0]])

  test "Save [LOCAL] keystore after [LOCAL] keystore with different id":
    let
      res1 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      res2 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey1, curCookedKey1, curSigningPath,
                          "", mode = Fast)
      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk

      validatorsCount == 2
      secretsCount == 2

      dirExists(curKeystoreDir0)
      not(fileExists(remoteKeystoreFile0))
      fileExists(localKeystoreFile0)
      fileExists(curSecretsFile0)

      dirExists(curKeystoreDir1)
      not(fileExists(remoteKeystoreFile1))
      fileExists(localKeystoreFile1)
      fileExists(curSecretsFile1)

      namesEqual(validatorPubKeys,
                 [MultipleKeystoreNames[0], MultipleKeystoreNames[1]])

  test "Save [REMOTE] keystore after [REMOTE] keystore with different id":
    let
      res1 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)
      res2 = saveKeystore(testValidatorsDir, curPublicKey1, MultipleRemoteUri)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk

      validatorsCount == 2
      secretsCount == 0

      dirExists(curKeystoreDir0)
      fileExists(remoteKeystoreFile0)
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      dirExists(curKeystoreDir1)
      fileExists(remoteKeystoreFile1)
      not(fileExists(localKeystoreFile1))
      not(fileExists(curSecretsFile1))

      namesEqual(validatorPubKeys,
                 [MultipleKeystoreNames[0], MultipleKeystoreNames[1]])

  test "Save [LOCAL] keystore after [REMOTE] keystore with different id":
    let
      res1 = saveKeystore(testValidatorsDir, curPublicKey0, MultipleRemoteUri)
      res2 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey1, curCookedKey1, curSigningPath,
                          "", mode = Fast)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk

      validatorsCount == 2
      secretsCount == 1

      dirExists(curKeystoreDir0)
      fileExists(remoteKeystoreFile0)
      not(fileExists(localKeystoreFile0))
      not(fileExists(curSecretsFile0))

      dirExists(curKeystoreDir1)
      not(fileExists(remoteKeystoreFile1))
      fileExists(localKeystoreFile1)
      fileExists(curSecretsFile1)

      namesEqual(validatorPubKeys,
                 [MultipleKeystoreNames[0], MultipleKeystoreNames[1]])

  test "Save [REMOTE] keystore after [LOCAL] keystore with different id":
    let
      res1 = saveKeystore(rng[], testValidatorsDir, testSecretsDir,
                          curSigningKey0, curCookedKey0, curSigningPath,
                          "", mode = Fast)
      res2 = saveKeystore(testValidatorsDir, curPublicKey1, MultipleRemoteUri)

      validatorsCount = directoryItemsCount(testValidatorsDir)
      secretsCount = directoryItemsCount(testSecretsDir)

      validatorPubKeys = validatorPubKeysInDir(testValidatorsDir)

    check:
      res1.isOk
      res2.isOk

      validatorsCount == 2
      secretsCount == 1

      dirExists(curKeystoreDir0)
      not(fileExists(remoteKeystoreFile0))
      fileExists(localKeystoreFile0)
      fileExists(curSecretsFile0)

      dirExists(curKeystoreDir1)
      fileExists(remoteKeystoreFile1)
      not(fileExists(localKeystoreFile1))
      not(fileExists(curSecretsFile1))

      namesEqual(validatorPubKeys,
                 [MultipleKeystoreNames[0], MultipleKeystoreNames[1]])
