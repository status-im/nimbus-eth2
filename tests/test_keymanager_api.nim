# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[typetraits, os, options, json, sequtils, uri, algorithm],
  testutils/unittests, chronicles, stint, json_serialization, confutils,
  chronos, eth/keys, blscurve, libp2p/crypto/crypto as lcrypto,
  stew/[byteutils, io2], stew/shims/net,

  ../beacon_chain/spec/[crypto, keystore, eth2_merkleization],
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/eth2_apis/[rest_keymanager_calls, rest_keymanager_types],
  ../beacon_chain/validators/[keystore_management, slashing_protection_common],
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/rpc/rest_key_management_api,
  ../beacon_chain/[conf, filepath, beacon_node,
                   nimbus_beacon_node, beacon_node_status,
                   nimbus_validator_client],
  ../beacon_chain/validator_client/common,
  ../ncli/ncli_testnet,
  ./testutil

type
  KeymanagerToTest = object
    ident: string
    port: int
    validatorsDir: string
    secretsDir: string

  # Individual port numbers derived by adding `ord` to configurable base port
  PortKind {.pure.} = enum
    PeerToPeer,
    Metrics,
    KeymanagerBN,
    KeymanagerVC

const
  simulationDepositsCount = 128
  dataDir = "./test_keymanager_api"
  validatorsDir = dataDir / "validators"
  secretsDir = dataDir / "secrets"
  depositsFile = dataDir / "deposits.json"
  runtimeConfigFile = dataDir / "config.yaml"
  genesisFile = dataDir / "genesis.ssz"
  depositTreeSnapshotFile = dataDir / "deposit_tree_snapshot.ssz"
  bootstrapEnrFile = dataDir / "bootstrap_node.enr"
  tokenFilePath = dataDir / "keymanager-token.txt"
  defaultBasePort = 49000
  correctTokenValue = "some secret token"
  defaultFeeRecipient = Eth1Address.fromHex("0x000000000000000000000000000000000000DEAD")
  defaultGasLimit = 30_000_000

  newPrivateKeys = [
    "0x598c9b81749ba7bb8eb37781027359e3ffe87d0e1579e21c453ce22af0c05e35",
    "0x14e4470a1d8913ec0602048af78addf0fd7a37f591dd3feda828d10a10c0f6ff",
    "0x3b4498c4e26f83702ceeed5e32600ecb3e71f08fc4561215d0f0ced13bf5dbdf",
    "0x3cae8cf27c7e12549486f5613974661285d40596907a7fc39bac7c55a56660ab",
    "0x71fd9bb8eadcf64df9cc8e716652709492c16518f73f87c770a54fe8c80ac5ae",
    "0x4be74b7b0b0058dea2d4744e0069486500770f68296ac9b9bbd26df6749ed0ca",
    "0x10052305a5fda7805fb1e762fe6cbc47e43c5a54f34f008fa79c48fee1749db7",
    "0x3630f086fb9f1136fe077751031a16630e43d65ff64bb9fd3708adff81df5926"
  ]

  oldPublicKeys = [
    "0x94effccb0514f0f110a9680827e4f3769e53349e3b1c177e8c4f38b0e52e7842a4990212fe2edd2ce48b9b0bd02f3b04",
    "0x950bcb136ef15e737cd28cc8ba94a5584e30cf6cfa4f3d16215acbe46917633c09630208f379898a898b29bd59b2bd34",
    "0xaa96fddc809e0678b192cebd3a64873a339c7352eafaa88ab13bac84244e19b9afe2de8282320f5e0e7c155573f80ac3",
    "0xa0f1da63e35c7a159fc2f187d300cad9ef5f5e73e55f78c391e7bc2c2feabc2d9d63dfe99edd7058ad0ab9d7f14a1e1a",
    "0x9315ea03755881989b0d34e9594520d2ebca4d2f0fd955dafe42948a91840a2e812d1d61f26684c603a60c99e3537151",
    "0x88c9737238fa23ed8e485e17349c523fe3fe848eab173959d34e7f7f2c731fb896ab7c0b0877a40782a5cd529dc7b080",
    "0x995e1d9d9d467ca25b981a7ca0880e932ac418e5ebed9a834f3ead3fbec267986e28eb0243c562ae3b1995a600c1495c",
    "0x945ab594e8c9cf3d6251b86fddf6fbf970c1835cd14113098554f135a6c2cf7f21d2f7a08ae33726785a59ae4910fa51",
  ]

  oldPublicKeysUrl = HttpHostUri(parseUri("http://127.0.0.1/local"))

  newPublicKeys = [
    "0x80eadf027ad564a2f004616fa58f3add9caa700b20e9bf7e0b101be61406feb79f5e28ec8a5bb2a0689cc7b4c807afba",
    "0x8c6585f39fd3d2ed950ba4958f0050ec68e4e7e3200147687fa101bcf98977ebe144b03edc45906faae144549f11d8b9",
    "0xb3939c9ecfb3679de8aa7f81e8dfb9eaa51e958d165e8b963aa88767217ce03316e4bad74e7a475ed6009365d297e0cd",
    "0xb093029010dd400f49350db77b13e70c3d75f5286c2cc5d7f1d0865e251cc547764de85371583eba2b1810cf36a4feb1",
    "0x8893a6f03de181cc93537ebb89ed242f65f3722fe22cd7aaab71a4149a792b231e23e1575c12efb0d2934e6d7b755431",
    "0x88c475e022971f0698b50aa2c9dd91df8b1c9f1079cbe7b2243bb5dee3a5cb5c46e170f90165efecdc794e14ae5b8fd9",
    "0xa782e5161ba8e9ac135b0db3203a8c23aa61e19be6b9c198393d8b2b902bad8139863d9cf26bc2cbdc3b747bafc64606",
    "0xb33f17216dda29dba1a9257e75b3dd8446c9ea217b563c20950c43f64300f7bd3d5f0dfa02274cab988e594552b7189e"
  ]

  unusedPublicKeys = [
    "0xc22f17216dda29dba1a9257e75b3dd8446c9ea217b563c20950c43f64300f7bd3d5f0dfa02274cab988e594552b7232d",
    "0x0bbca63e35c7a159fc2f187d300cad9ef5f5e73e55f78c391e7bc2c2feabc2d9d63dfe99edd7058ad0ab9d7f14aade5f"
  ]

  newPublicKeysUrl = HttpHostUri(parseUri("http://127.0.0.1/remote"))

  nodeDataDir = dataDir / "node-0"
  nodeValidatorsDir = nodeDataDir / "validators"
  nodeSecretsDir = nodeDataDir / "secrets"

  vcDataDir = dataDir / "validator-0"
  vcValidatorsDir = vcDataDir / "validators"
  vcSecretsDir = vcDataDir / "secrets"

func specifiedFeeRecipient(x: int): Eth1Address =
  copyMem(addr result, unsafeAddr x, sizeof x)

proc contains*(keylist: openArray[KeystoreInfo], key: ValidatorPubKey): bool =
  for item in keylist:
    if item.validating_pubkey == key:
      return true
  false

proc contains*(keylist: openArray[KeystoreInfo], key: string): bool =
  let pubkey = ValidatorPubKey.fromHex(key).tryGet()
  contains(keylist, pubkey)

proc prepareNetwork =
  let
    rng = keys.newRng()
    mnemonic = generateMnemonic(rng[])
    seed = getSeed(mnemonic, KeystorePass.init "")
    cfg = defaultRuntimeConfig

  let vres = secureCreatePath(validatorsDir)
  if vres.isErr():
    warn "Could not create validators folder",
          path = validatorsDir, err = ioErrorMsg(vres.error)

  let sres = secureCreatePath(secretsDir)
  if sres.isErr():
    warn "Could not create secrets folder",
          path = secretsDir, err = ioErrorMsg(sres.error)

  let deposits = generateDeposits(
    cfg,
    rng[],
    seed,
    0, simulationDepositsCount,
    validatorsDir,
    secretsDir,
    @[],
    0,
    0,
    KeystoreMode.Fast)

  if deposits.isErr:
    fatal "Failed to generate deposits", err = deposits.error
    quit 1

  let launchPadDeposits =
    mapIt(deposits.value, LaunchPadDeposit.init(cfg, it))

  Json.saveFile(depositsFile, launchPadDeposits)
  notice "Deposit data written", filename = depositsFile

  let runtimeConfigWritten = secureWriteFile(runtimeConfigFile, """
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_EPOCH: 0
""")

  if runtimeConfigWritten.isOk:
    notice "Run-time config written", filename = runtimeConfigFile
  else:
    fatal "Failed to write run-time config", filename = runtimeConfigFile
    quit 1

  let createTestnetConf = try: ncli_testnet.CliConfig.load(cmdLine = mapIt([
    "createTestnet",
    "--data-dir=" & dataDir,
    "--total-validators=" & $simulationDepositsCount,
    "--deposits-file=" & depositsFile,
    "--output-genesis=" & genesisFile,
    "--output-deposit-tree-snapshot=" & depositTreeSnapshotFile,
    "--output-bootstrap-file=" & bootstrapEnrFile,
    "--netkey-file=network_key.json",
    "--insecure-netkey-password=true",
    "--genesis-offset=0"], it))
  except Exception as exc: # TODO Fix confutils exceptions
    raiseAssert exc.msg

  doCreateTestnet(createTestnetConf, rng[])

  let tokenFileRes = secureWriteFile(tokenFilePath, correctTokenValue)
  if tokenFileRes.isErr:
    fatal "Failed to create token file", err = deposits.error
    quit 1

proc copyHalfValidators(dstDataDir: string, firstHalf: bool) =
  let dstValidatorsDir = dstDataDir / "validators"

  block:
    let status = secureCreatePath(dstValidatorsDir)
    if status.isErr():
      fatal "Could not create node validators folder",
             path = dstValidatorsDir, err = ioErrorMsg(status.error)
      quit 1

  let dstSecretsDir = dstDataDir / "secrets"

  block:
    let status = secureCreatePath(dstSecretsDir)
    if status.isErr():
      fatal "Could not create node secrets folder",
             path = dstSecretsDir, err = ioErrorMsg(status.error)
      quit 1

  var validatorIdx = 0
  for validator in walkDir(validatorsDir):
    if (validatorIdx < simulationDepositsCount div 2) == firstHalf:
      let
        currValidator = os.splitPath(validator.path).tail
        secretFile = secretsDir / currValidator
        secretRes = readAllChars(secretFile)

      if secretRes.isErr:
        fatal "Failed to read secret file",
               path = secretFile, err = $secretRes.error
        quit 1

      let
        dstSecretFile = dstSecretsDir / currValidator
        secretFileStatus = secureWriteFile(dstSecretFile, secretRes.get)

      if secretFileStatus.isErr:
        fatal "Failed to write secret file",
               path = dstSecretFile, err = $secretFileStatus.error
        quit 1

      let
        dstValidatorDir = dstDataDir / "validators" / currValidator
        validatorDirRes = secureCreatePath(dstValidatorDir)

      if validatorDirRes.isErr:
        fatal "Failed to create validator dir",
               path = dstValidatorDir, err = $validatorDirRes.error
        quit 1

      let
        keystoreFile = validatorsDir / currValidator / "keystore.json"
        readKeystoreRes = readAllChars(keystoreFile)

      if readKeystoreRes.isErr:
        fatal "Failed to read keystore file",
               path = keystoreFile, err = $readKeystoreRes.error
        quit 1

      let
        dstKeystore = dstValidatorDir / "keystore.json"
        writeKeystoreRes = secureWriteFile(dstKeystore, readKeystoreRes.get)

      if writeKeystoreRes.isErr:
        fatal "Failed to write keystore file",
               path = dstKeystore, err = $writeKeystoreRes.error
        quit 1

    inc validatorIdx

proc addPreTestRemoteKeystores(validatorsDir: string) =
  for item in oldPublicKeys:
    let key = ValidatorPubKey.fromHex(item).tryGet()
    let res = saveKeystore(validatorsDir, key, oldPublicKeysUrl)
    if res.isErr():
      fatal "Failed to create remote keystore file",
            validatorsDir = nodeValidatorsDir, key,
            err = res.error
      quit 1

proc startBeaconNode(basePort: int) {.raises: [Defect, CatchableError].} =
  let rng = keys.newRng()

  copyHalfValidators(nodeDataDir, true)
  addPreTestRemoteKeystores(nodeValidatorsDir)

  let runNodeConf = try: BeaconNodeConf.load(cmdLine = mapIt([
    "--tcp-port=" & $(basePort + PortKind.PeerToPeer.ord),
    "--udp-port=" & $(basePort + PortKind.PeerToPeer.ord),
    "--discv5=off",
    "--network=" & dataDir,
    "--data-dir=" & nodeDataDir,
    "--validators-dir=" & nodeValidatorsDir,
    "--secrets-dir=" & nodeSecretsDir,
    "--metrics-address=127.0.0.1",
    "--metrics-port=" & $(basePort + PortKind.Metrics.ord),
    "--rest=true",
    "--rest-address=127.0.0.1",
    "--rest-port=" & $(basePort + PortKind.KeymanagerBN.ord),
    "--no-el",
    "--keymanager=true",
    "--keymanager-address=127.0.0.1",
    "--keymanager-port=" & $(basePort + PortKind.KeymanagerBN.ord),
    "--keymanager-token-file=" & tokenFilePath,
    "--suggested-fee-recipient=" & $defaultFeeRecipient,
    "--doppelganger-detection=off"], it))
  except Exception as exc: # TODO fix confutils exceptions
    raiseAssert exc.msg

  let
    metadata = loadEth2NetworkMetadata(dataDir)
    node = BeaconNode.init(rng, runNodeConf, metadata)

  node.start() # This will run until the node is terminated by
               #  setting its `bnStatus` to `Stopping`.

  # os.removeDir dataDir

proc startValidatorClient(basePort: int) {.async, thread.} =
  let rng = keys.newRng()

  copyHalfValidators(vcDataDir, false)
  addPreTestRemoteKeystores(vcValidatorsDir)

  let runValidatorClientConf = try: ValidatorClientConf.load(cmdLine = mapIt([
    "--beacon-node=http://127.0.0.1:" & $(basePort + PortKind.KeymanagerBN.ord),
    "--data-dir=" & vcDataDir,
    "--validators-dir=" & vcValidatorsDir,
    "--secrets-dir=" & vcSecretsDir,
    "--suggested-fee-recipient=" & $defaultFeeRecipient,
    "--keymanager=true",
    "--keymanager-address=127.0.0.1",
    "--keymanager-port=" & $(basePort + PortKind.KeymanagerVC.ord),
    "--keymanager-token-file=" & tokenFilePath], it))
  except:
    quit 1

  await runValidatorClient(runValidatorClientConf, rng)

const
  password = "7465737470617373776f7264f09f9491"
  # This is taken from the offical test vectors in test_keystores.nim
  secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
  iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"
  secretNetBytes = hexToSeqByte "08021220fe442379443d6e2d7d75d3a58f96fbb35f0a9c7217796825fc9040e3b89c5736"

proc listLocalValidators(validatorsDir,
                         secretsDir: string): seq[ValidatorPubKey] {.
     raises: [Defect].} =
  var validators: seq[ValidatorPubKey]
  try:
    for el in listLoadableKeys(validatorsDir, secretsDir,
                               {KeystoreKind.Local}):
      validators.add el.toPubKey()
  except OSError as err:
    error "Failure to list the validator directories",
          validatorsDir, secretsDir, err = err.msg
  validators

proc listRemoteValidators(validatorsDir,
                          secretsDir: string): seq[ValidatorPubKey] {.
     raises: [Defect].} =
  var validators: seq[ValidatorPubKey]
  try:
    for el in listLoadableKeys(validatorsDir, secretsDir,
                               {KeystoreKind.Remote}):
      validators.add el.toPubKey()
  except OSError as err:
    error "Failure to list the validator directories",
          validatorsDir, secretsDir, err = err.msg
  validators

proc `==`(a: seq[ValidatorPubKey],
          b: seq[KeystoreInfo | RemoteKeystoreInfo]): bool =
  if len(a) != len(b):
    return false
  var indices: seq[int]
  for publicKey in a:
    let index =
      block:
        var res = -1
        for k, v in b.pairs():
          let key =
            when b is seq[KeystoreInfo]:
              v.validating_pubkey
            else:
              v.pubkey
          if key == publicKey:
            res = k
            break
        res
    if (index == -1) or (index in indices):
      return false
    indices.add(index)
  true

proc runTests(keymanager: KeymanagerToTest) {.async.} =
  let
    client = RestClientRef.new(initTAddress("127.0.0.1", keymanager.port))
    rng = keys.newRng()
    privateKey = ValidatorPrivKey.fromRaw(secretBytes).get

    allValidators = listLocalValidators(
      keymanager.validatorsDir, keymanager.secretsDir)

  let
    newKeystore = createKeystore(
      kdfPbkdf2, rng[], privateKey,
      KeystorePass.init password,
      salt = salt, iv = iv,
      description = "This is a test keystore that uses PBKDF2 to secure the secret",
      path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))

    importKeystoresBody1 =
      block:
        var
          res1: seq[Keystore]
          res2: seq[string]
        for key in newPrivateKeys:
          let privateKey = ValidatorPrivKey.fromHex(key).tryGet()
          let store = createKeystore(kdfPbkdf2, rng[], privateKey,
            KeystorePass.init password, salt = salt, iv = iv,
            description = "Test keystore",
            path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))
          res1.add(store)
          res2.add(password)
        KeystoresAndSlashingProtection(
          keystores: res1,
          passwords: res2,
        )

    deleteKeysBody1 =
      block:
        var res: seq[ValidatorPubKey]
        for item in newPrivateKeys:
          let privateKey = ValidatorPrivKey.fromHex(item).tryGet()
          let publicKey = privateKey.toPubKey().toPubKey()
          res.add(publicKey)
        DeleteKeystoresBody(
          pubkeys: res
        )

    importKeystoresBody = KeystoresAndSlashingProtection(
      keystores: @[newKeystore],
      passwords: @[password],
    )

    deleteKeysBody = DeleteKeystoresBody(
      pubkeys: @[privateKey.toPubKey.toPubKey])

    importRemoteKeystoresBody =
      block:
        var res: seq[RemoteKeystoreInfo]
        # Adding keys which are already present in filesystem
        for item in oldPublicKeys:
          let key = ValidatorPubKey.fromHex(item).tryGet()
          res.add(RemoteKeystoreInfo(pubkey: key, url: newPublicKeysUrl))
        # Adding keys which are new
        for item in newPublicKeys:
          let key = ValidatorPubKey.fromHex(item).tryGet()
          res.add(RemoteKeystoreInfo(pubkey: key, url: newPublicKeysUrl))
        # Adding non-remote keys which are already present in filesystem
        res.add(RemoteKeystoreInfo(pubkey: allValidators[0],
                                   url: newPublicKeysUrl))
        res.add(RemoteKeystoreInfo(pubkey: allValidators[1],
                                   url: newPublicKeysUrl))
        ImportRemoteKeystoresBody(remote_keys: res)

  template expectedImportStatus(i: int): string =
      if i < 8:
        "duplicate"
      elif i == 16 or i == 17:
        "duplicate"
      else:
        "imported"

  let
    deleteRemoteKeystoresBody1 =
      block:
        var res: seq[ValidatorPubKey]
        for item in oldPublicKeys:
          let key = ValidatorPubKey.fromHex(item).tryGet()
          res.add(key)
        DeleteKeystoresBody(pubkeys: res)

    deleteRemoteKeystoresBody2 =
      block:
        var res: seq[ValidatorPubKey]
        for item in newPublicKeys:
          let key = ValidatorPubKey.fromHex(item).tryGet()
          res.add(key)
        DeleteKeystoresBody(pubkeys: res)

    deleteRemoteKeystoresBody3 =
      block:
        DeleteKeystoresBody(
          pubkeys: @[
            ValidatorPubKey.fromHex(newPublicKeys[0]).tryGet(),
            ValidatorPubKey.fromHex(newPublicKeys[1]).tryGet()
          ]
        )

    deleteRemoteKeystoresBody4 =
      block:
        DeleteKeystoresBody(
          pubkeys: @[
            ValidatorPubKey.fromHex(oldPublicKeys[0]).tryGet(),
            ValidatorPubKey.fromHex(oldPublicKeys[1]).tryGet(),
            allValidators[0],
            allValidators[1]
          ]
        )

    testFlavour = " [" & keymanager.ident & "]" & preset()

  suite "Serialization/deserialization" & testFlavour:
    proc `==`(a, b: Kdf): bool =
      if (a.function != b.function) or (a.message != b.message):
        return false
      case a.function
      of KdfKind.kdfPbkdf2:
        (a.pbkdf2Params.dklen == b.pbkdf2Params.dklen) and
          (a.pbkdf2Params.c == b.pbkdf2Params.c) and
          (a.pbkdf2Params.prf == b.pbkdf2Params.prf) and
          (seq[byte](a.pbkdf2Params.salt) == seq[byte](b.pbkdf2Params.salt))
      of KdfKind.kdfScrypt:
        (a.scryptParams.dklen == b.scryptParams.dklen) and
          (a.scryptParams.n == b.scryptParams.n) and
          (a.scryptParams.p == b.scryptParams.p) and
          (a.scryptParams.r == b.scryptParams.r) and
          (seq[byte](a.scryptParams.salt) == seq[byte](b.scryptParams.salt))

    proc `==`(a, b: Checksum): bool =
      if a.function != b.function:
        return false
      case a.function
      of ChecksumFunctionKind.sha256Checksum:
        a.message.data == b.message.data

    proc `==`(a, b: Cipher): bool =
      if (a.function != b.function) or
         (seq[byte](a.message) != seq[byte](b.message)):
        return false
      case a.function
      of CipherFunctionKind.aes128CtrCipher:
        seq[byte](a.params.iv) == seq[byte](b.params.iv)

    proc `==`(a, b: Crypto): bool =
      (a.kdf == b.kdf) and (a.checksum == b.checksum) and
        (a.cipher == b.cipher)

    proc `==`(a, b: Keystore): bool =
      (a.crypto == b.crypto) and (a.pubkey == b.pubkey) and
        (string(a.path) == string(b.path)) and
        (a.description == b.description) and (a.uuid == b.uuid) and
        (a.version == b.version)

    test "Deserialization test vectors":
      let
        kdf1 = Kdf(
          function: KdfKind.kdfPbkdf2,
          pbkdf2Params: Pbkdf2Params(
            dklen: 32'u64,
            c: 262144'u64,
            prf: PrfKind.HmacSha256,
            salt: Pbkdf2Salt(hexToSeqByte("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"))
          ),
          message: ""
        )
        kdf2 = Kdf(
          function: KdfKind.kdfScrypt,
          scryptParams: ScryptParams(
            dklen: 32'u64, n: 262144, p: 1, r: 8,
            salt: ScryptSalt(hexToSeqByte("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"))),
          message: ""
        )
        checksum1 = Checksum(
          function: ChecksumFunctionKind.sha256Checksum,
          params: Sha256Params(),
          message: Sha256Digest(MDigest[256].fromHex("0x88c0059314a3db1b2e86d4b0d37ac7ade7c6e56e3d3e34af298254f35c8b501e"))
        )
        checksum2 = Checksum(
          function: ChecksumFunctionKind.sha256Checksum,
          params: Sha256Params(),
          message: Sha256Digest(MDigest[256].fromHex("0xadb59d10d2436c12f2fe229f27ec598739da92686485e9fed5255d3ed9bb1c1f"))
        )
        checksum3 = Checksum(
          function: ChecksumFunctionKind.sha256Checksum,
          params: Sha256Params(),
          message: Sha256Digest(MDigest[256].fromHex("0xea4d7f495ac74bbf431ef340f15ee1aea75811bd1bab8dd64b3c2dfc041d5d90"))
        )
        checksum4 = Checksum(
          function: ChecksumFunctionKind.sha256Checksum,
          params: Sha256Params(),
          message: Sha256Digest(MDigest[256].fromHex("0x71ed99dab563f1e9f1190b0de9d92d3266df2223036e7dc3ca9d9599478fe5a4"))
        )
        cipher1 = Cipher(
          function: CipherFunctionKind.aes128CtrCipher,
          params: Aes128CtrParams(iv: Aes128CtrIv(hexToSeqByte("264daa3f303d7259501c93d997d84fe6"))),
          message: CipherBytes(hexToSeqByte("c071f12ec97eb449422de643e737924e02eec266f3b56cde476eae4fad5c6e64"))
        )
        cipher2 = Cipher(
          function: CipherFunctionKind.aes128CtrCipher,
          params: Aes128CtrParams(iv: Aes128CtrIv(hexToSeqByte("264daa3f303d7259501c93d997d84fe6"))),
          message: CipherBytes(hexToSeqByte("8d192da5a06c001eca9c954812ce165d007c889d7711b12faa7a9d6f4d5cc6ae"))
        )
        cipher3 = Cipher(
          function: CipherFunctionKind.aes128CtrCipher,
          params: Aes128CtrParams(iv: Aes128CtrIv(hexToSeqByte("264daa3f303d7259501c93d997d84fe6"))),
          message: CipherBytes(hexToSeqByte("c40a44096120e406a011ec5a22d7cbb24126436c471e21b10f078c722c6d0c3f"))
        )
        cipher4 = Cipher(
          function: CipherFunctionKind.aes128CtrCipher,
          params: Aes128CtrParams(iv: Aes128CtrIv(hexToSeqByte("264daa3f303d7259501c93d997d84fe6"))),
          message: CipherBytes(hexToSeqByte("896298820832505128a09f51d72e4fa143b40997c3bafc40e213bf52cc6da4f5"))
        )
        keystore1 = Keystore(
          crypto: Crypto(kdf: kdf1, checksum: checksum1, cipher: cipher1),
          pubkey: ValidatorPubKey.fromHex("0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798").get(),
          path: KeyPath("m/12381/60/0/0"),
          description: some "Test keystore",
          uuid: "a3331c0c-a013-4754-a122-9988b3381fec",
          version: 4
        )
        keystore2 = Keystore(
          crypto: Crypto(kdf: kdf1, checksum: checksum2, cipher: cipher2),
          pubkey: ValidatorPubKey.fromHex("0xa00d2954717425ce047e0928e5f4ec7c0e3bbe1058db511303fd659770ddace686ee2e22ac180422e516f4c503eb2228").get(),
          path: KeyPath("m/12381/60/0/0"),
          description: some "Test keystore",
          uuid: "905dd873-48af-416a-8c80-4283d5af84f9",
          version: 4
        )
        keystore3 = Keystore(
          crypto: Crypto(kdf: kdf2, checksum: checksum3, cipher: cipher3),
          pubkey: ValidatorPubKey.fromHex("0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798").get(),
          path: KeyPath("m/12381/60/0/0"),
          description: some "Test keystore",
          uuid: "ad1bf334-faaa-4257-8e28-81a45722e87b",
          version: 4
        )
        keystore4 = Keystore(
          crypto: Crypto(kdf: kdf2, checksum: checksum4, cipher: cipher4),
          pubkey: ValidatorPubKey.fromHex("0xa00d2954717425ce047e0928e5f4ec7c0e3bbe1058db511303fd659770ddace686ee2e22ac180422e516f4c503eb2228").get(),
          path: KeyPath("m/12381/60/0/0"),
          description: some "Test keystore",
          uuid: "d91bcde8-8bf5-45c6-b04d-c10d99ae9b6b",
          version: 4
        )

      const
        Vector1 = r"{""keystores"":[""{\""crypto\"":{\""kdf\"":{\""function\"":\""pbkdf2\"",\""params\"":{\""dklen\"":32,\""c\"":262144,\""prf\"":\""hmac-sha256\"",\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0x88c0059314a3db1b2e86d4b0d37ac7ade7c6e56e3d3e34af298254f35c8b501e\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""c071f12ec97eb449422de643e737924e02eec266f3b56cde476eae4fad5c6e64\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""a3331c0c-a013-4754-a122-9988b3381fec\"",\""name\"":\""named-a3331c0c-a013-4754-a122-9988b3381fec\"",\""version\"":4}""],""passwords"":[""7465737470617373776f7264f09f9491""]}"
        Vector2 = r"{""keystores"":[""{\""crypto\"":{\""kdf\"":{\""function\"":\""pbkdf2\"",\""params\"":{\""dklen\"":32,\""c\"":262144,\""prf\"":\""hmac-sha256\"",\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0x88c0059314a3db1b2e86d4b0d37ac7ade7c6e56e3d3e34af298254f35c8b501e\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""c071f12ec97eb449422de643e737924e02eec266f3b56cde476eae4fad5c6e64\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""a3331c0c-a013-4754-a122-9988b3381fec\"",\""version\"":4}"",""{\""crypto\"":{\""kdf\"":{\""function\"":\""pbkdf2\"",\""params\"":{\""dklen\"":32,\""c\"":262144,\""prf\"":\""hmac-sha256\"",\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0xadb59d10d2436c12f2fe229f27ec598739da92686485e9fed5255d3ed9bb1c1f\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""8d192da5a06c001eca9c954812ce165d007c889d7711b12faa7a9d6f4d5cc6ae\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xa00d2954717425ce047e0928e5f4ec7c0e3bbe1058db511303fd659770ddace686ee2e22ac180422e516f4c503eb2228\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""905dd873-48af-416a-8c80-4283d5af84f9\"",\""version\"":4}""],""passwords"":[""7465737470617373776f7264f09f9491"",""7465737470617373776f7264f09f9491""]}"
        Vector3 = r"{""keystores"":[""{\""crypto\"":{\""kdf\"":{\""function\"":\""scrypt\"",\""params\"":{\""dklen\"":32,\""n\"":262144,\""p\"":1,\""r\"":8,\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0xea4d7f495ac74bbf431ef340f15ee1aea75811bd1bab8dd64b3c2dfc041d5d90\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""c40a44096120e406a011ec5a22d7cbb24126436c471e21b10f078c722c6d0c3f\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""ad1bf334-faaa-4257-8e28-81a45722e87b\"",\""version\"":4}""],""passwords"":[""7465737470617373776f7264f09f9491""]}"
        Vector4 = r"{""keystores"":[""{\""crypto\"":{\""kdf\"":{\""function\"":\""scrypt\"",\""params\"":{\""dklen\"":32,\""n\"":262144,\""p\"":1,\""r\"":8,\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0xea4d7f495ac74bbf431ef340f15ee1aea75811bd1bab8dd64b3c2dfc041d5d90\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""c40a44096120e406a011ec5a22d7cbb24126436c471e21b10f078c722c6d0c3f\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""ad1bf334-faaa-4257-8e28-81a45722e87b\"",\""version\"":4}"",""{\""crypto\"":{\""kdf\"":{\""function\"":\""scrypt\"",\""params\"":{\""dklen\"":32,\""n\"":262144,\""p\"":1,\""r\"":8,\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0x71ed99dab563f1e9f1190b0de9d92d3266df2223036e7dc3ca9d9599478fe5a4\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""896298820832505128a09f51d72e4fa143b40997c3bafc40e213bf52cc6da4f5\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xa00d2954717425ce047e0928e5f4ec7c0e3bbe1058db511303fd659770ddace686ee2e22ac180422e516f4c503eb2228\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""d91bcde8-8bf5-45c6-b04d-c10d99ae9b6b\"",\""version\"":4}""],""passwords"":[""7465737470617373776f7264f09f9491"",""7465737470617373776f7264f09f9491""]}"
        Vector5 = r"{""keystores"":[""{\""crypto\"":{\""kdf\"":{\""function\"":\""pbkdf2\"",\""params\"":{\""dklen\"":32,\""c\"":262144,\""prf\"":\""hmac-sha256\"",\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0x88c0059314a3db1b2e86d4b0d37ac7ade7c6e56e3d3e34af298254f35c8b501e\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""c071f12ec97eb449422de643e737924e02eec266f3b56cde476eae4fad5c6e64\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""a3331c0c-a013-4754-a122-9988b3381fec\"",\""version\"":4}"",""{\""crypto\"":{\""kdf\"":{\""function\"":\""scrypt\"",\""params\"":{\""dklen\"":32,\""n\"":262144,\""p\"":1,\""r\"":8,\""salt\"":\""d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3\""},\""message\"":\""\""},\""checksum\"":{\""function\"":\""sha256\"",\""params\"":{},\""message\"":\""0xea4d7f495ac74bbf431ef340f15ee1aea75811bd1bab8dd64b3c2dfc041d5d90\""},\""cipher\"":{\""function\"":\""aes-128-ctr\"",\""params\"":{\""iv\"":\""264daa3f303d7259501c93d997d84fe6\""},\""message\"":\""c40a44096120e406a011ec5a22d7cbb24126436c471e21b10f078c722c6d0c3f\""}},\""description\"":\""Test keystore\"",\""pubkey\"":\""0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798\"",\""path\"":\""m/12381/60/0/0\"",\""uuid\"":\""ad1bf334-faaa-4257-8e28-81a45722e87b\"",\""version\"":4}""],""passwords"":[""7465737470617373776f7264f09f9491"", ""7465737470617373776f7264f09f9491""]}"

      let
        r1 = decodeBytes(KeystoresAndSlashingProtection,
                         Vector1.toOpenArrayByte(0, len(Vector1) - 1),
                         Opt.some(getContentType("application/json").get()))
        r2 = decodeBytes(KeystoresAndSlashingProtection,
                         Vector2.toOpenArrayByte(0, len(Vector2) - 1),
                         Opt.some(getContentType("application/json").get()))
        r3 = decodeBytes(KeystoresAndSlashingProtection,
                         Vector3.toOpenArrayByte(0, len(Vector3) - 1),
                         Opt.some(getContentType("application/json").get()))
        r4 = decodeBytes(KeystoresAndSlashingProtection,
                         Vector4.toOpenArrayByte(0, len(Vector4) - 1),
                         Opt.some(getContentType("application/json").get()))
        r5 = decodeBytes(KeystoresAndSlashingProtection,
                         Vector5.toOpenArrayByte(0, len(Vector5) - 1),
                         Opt.some(getContentType("application/json").get()))

      check:
        r1.isOk() == true
        r2.isOk() == true
        r3.isOk() == true
        r4.isOk() == true
        r5.isOk() == true

      let
        d1 = r1.get()
        d2 = r2.get()
        d3 = r3.get()
        d4 = r4.get()
        d5 = r5.get()

      check:
        len(d1.keystores) == 1
        len(d2.keystores) == 2
        len(d3.keystores) == 1
        len(d4.keystores) == 2
        len(d5.keystores) == 2
        d1.keystores[0] == keystore1
        d2.keystores[0] == keystore1
        d2.keystores[1] == keystore2
        d3.keystores[0] == keystore3
        d4.keystores[0] == keystore3
        d4.keystores[1] == keystore4
        d5.keystores[0] == keystore1
        d5.keystores[1] == keystore3
        len(d1.passwords) == 1
        len(d2.passwords) == 2
        len(d3.passwords) == 1
        len(d4.passwords) == 2
        len(d5.passwords) == 2
        d1.passwords == @["7465737470617373776f7264f09f9491"]
        d2.passwords == @["7465737470617373776f7264f09f9491",
                          "7465737470617373776f7264f09f9491"]
        d3.passwords == @["7465737470617373776f7264f09f9491"]
        d4.passwords == @["7465737470617373776f7264f09f9491",
                          "7465737470617373776f7264f09f9491"]
        d5.passwords == @["7465737470617373776f7264f09f9491",
                          "7465737470617373776f7264f09f9491"]

  suite "ListKeys requests" & testFlavour:
    asyncTest "Correct token provided" & testFlavour:
      let
        filesystemKeys = sorted listLocalValidators(keymanager.validatorsDir,
                                                    keymanager.secretsDir)
        apiKeys = sorted (await client.listKeys(correctTokenValue)).data

      check filesystemKeys == apiKeys

    asyncTest "Missing Authorization header" & testFlavour:
      let
        response = await client.listKeysPlain()
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let
        response = await client.listKeysPlain(
          extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let
        response = await client.listKeysPlain(
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 403
        responseJson["message"].getStr() == InvalidAuthorizationError

      expect RestError:
        let keystores = await client.listKeys("Invalid Token")

  suite "ImportKeystores requests" & testFlavour:
    asyncTest "ImportKeystores/ListKeystores/DeleteKeystores" & testFlavour:
      let
        response1 = await client.importKeystoresPlain(
          importKeystoresBody1,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson1 = Json.decode(response1.data, JsonNode)

      check response1.status == 200
      for i in 0 ..< 8:
        check:
          responseJson1["data"][i]["status"].getStr() == "imported"
          responseJson1["data"][i]["message"].getStr() == ""

      let
        filesystemKeys1 = sorted(
          listLocalValidators(keymanager.validatorsDir,
                              keymanager.secretsDir))
        apiKeystores1 = sorted((await client.listKeys(correctTokenValue)).data)

      check:
        filesystemKeys1 == apiKeystores1
        importKeystoresBody1.keystores[0].pubkey in filesystemKeys1
        importKeystoresBody1.keystores[1].pubkey in filesystemKeys1
        importKeystoresBody1.keystores[2].pubkey in filesystemKeys1
        importKeystoresBody1.keystores[3].pubkey in filesystemKeys1
        importKeystoresBody1.keystores[4].pubkey in filesystemKeys1
        importKeystoresBody1.keystores[5].pubkey in filesystemKeys1
        importKeystoresBody1.keystores[6].pubkey in filesystemKeys1
        importKeystoresBody1.keystores[7].pubkey in filesystemKeys1

      let
        response2 = await client.importKeystoresPlain(
          importKeystoresBody1,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson2 = Json.decode(response2.data, JsonNode)

      check response2.status == 200
      for i in 0 ..< 8:
        check:
          responseJson2["data"][i]["status"].getStr() == "duplicate"
          responseJson2["data"][i]["message"].getStr() == ""

      let
        response3 = await client.deleteKeysPlain(
          deleteKeysBody1,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson3 = Json.decode(response3.data, JsonNode)

      check response3.status == 200
      for i in 0 ..< 8:
        check:
          responseJson3["data"][i]["status"].getStr() == "deleted"
          responseJson3["data"][i]["message"].getStr() == ""

      let
        filesystemKeys2 = sorted(
          listLocalValidators(keymanager.validatorsDir,
                              keymanager.secretsDir))
        apiKeystores2 = sorted((await client.listKeys(correctTokenValue)).data)

      check:
        filesystemKeys2 == apiKeystores2
        deleteKeysBody1.pubkeys[0] notin filesystemKeys2
        deleteKeysBody1.pubkeys[1] notin filesystemKeys2
        deleteKeysBody1.pubkeys[2] notin filesystemKeys2
        deleteKeysBody1.pubkeys[3] notin filesystemKeys2
        deleteKeysBody1.pubkeys[4] notin filesystemKeys2
        deleteKeysBody1.pubkeys[5] notin filesystemKeys2
        deleteKeysBody1.pubkeys[6] notin filesystemKeys2
        deleteKeysBody1.pubkeys[7] notin filesystemKeys2

    asyncTest "Missing Authorization header" & testFlavour:
      let
        response = await client.importKeystoresPlain(importKeystoresBody)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let
        response = await client.importKeystoresPlain(
          importKeystoresBody,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let
        response = await client.importKeystoresPlain(
          importKeystoresBody,
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 403
        responseJson["message"].getStr() == InvalidAuthorizationError

  suite "DeleteKeys requests" & testFlavour:
    asyncTest "Deleting not existing key" & testFlavour:
      let
        response = await client.deleteKeysPlain(
          deleteKeysBody,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 200
        responseJson["data"][0]["status"].getStr() == "not_found"
        responseJson["data"][0]["message"].getStr() == ""

    asyncTest "Missing Authorization header" & testFlavour:
      let
        response = await client.deleteKeysPlain(deleteKeysBody)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let
        response = await client.deleteKeysPlain(
          deleteKeysBody,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let
        response = await client.deleteKeysPlain(
          deleteKeysBody,
          extraHeaders = @[("Authorization", "Bearer XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 403
        responseJson["message"].getStr() == InvalidAuthorizationError

  suite "ListRemoteKeys requests" & testFlavour:
    asyncTest "Correct token provided" & testFlavour:
      let
        filesystemKeys = sorted(
          listRemoteValidators(keymanager.validatorsDir,
                               keymanager.secretsDir))
        apiKeystores = sorted((
          await client.listRemoteKeys(correctTokenValue)).data)

      check filesystemKeys == apiKeystores

    asyncTest "Missing Authorization header" & testFlavour:
      let
        response = await client.listRemoteKeysPlain()
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let
        response = await client.listRemoteKeysPlain(
          extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let
        response = await client.listRemoteKeysPlain(
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 403
        responseJson["message"].getStr() == InvalidAuthorizationError

      expect RestError:
        let keystores = await client.listKeys("Invalid Token")

  suite "Fee recipient management" & testFlavour:
    asyncTest "Missing Authorization header" & testFlavour:
      let pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")

      block:
        let
          response = await client.listFeeRecipientPlain(pubkey)
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.setFeeRecipientPlain(
            pubkey,
            default SetFeeRecipientRequest)
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.deleteFeeRecipientPlain(pubkey, EmptyBody())
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")

      block:
        let
          response = await client.listFeeRecipientPlain(
            pubkey,
            extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.setFeeRecipientPlain(
            pubkey,
            default SetFeeRecipientRequest,
            extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError


      block:
        let
          response = await client.deleteFeeRecipientPlain(
            pubkey,
            EmptyBody(),
            extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")

      block:
        let
          response = await client.listFeeRecipientPlain(
            pubkey,
            extraHeaders = @[("Authorization", "Bearer InvalidToken")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 403
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.setFeeRecipientPlain(
            pubkey,
            default SetFeeRecipientRequest,
            extraHeaders = @[("Authorization", "Bearer InvalidToken")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 403
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.deleteFeeRecipientPlain(
            pubkey,
            EmptyBody(),
            extraHeaders = @[("Authorization", "Bearer InvalidToken")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 403
          responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Obtaining the fee recpient of a missing validator returns 404" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(unusedPublicKeys[0]).expect("valid key")
        response = await client.listFeeRecipientPlain(
          pubkey,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])

      check:
        response.status == 404

    asyncTest "Setting the fee recipient on a missing validator creates a record for it" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(unusedPublicKeys[1]).expect("valid key")
        feeRecipient = specifiedFeeRecipient(1)

      await client.setFeeRecipient(pubkey, feeRecipient, correctTokenValue)
      let resultFromApi = await client.listFeeRecipient(pubkey, correctTokenValue)

      check:
        resultFromApi == feeRecipient

    asyncTest "Obtaining the fee recpient of an unconfigured validator returns the suggested default" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")
        resultFromApi = await client.listFeeRecipient(pubkey, correctTokenValue)

      check:
        resultFromApi == defaultFeeRecipient

    asyncTest "Configuring the fee recpient" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(oldPublicKeys[1]).expect("valid key")
        firstFeeRecipient = specifiedFeeRecipient(2)

      await client.setFeeRecipient(pubkey, firstFeeRecipient, correctTokenValue)

      let firstResultFromApi = await client.listFeeRecipient(pubkey, correctTokenValue)
      check:
        firstResultFromApi == firstFeeRecipient

      let secondFeeRecipient = specifiedFeeRecipient(3)
      await client.setFeeRecipient(pubkey, secondFeeRecipient, correctTokenValue)

      let secondResultFromApi = await client.listFeeRecipient(pubkey, correctTokenValue)
      check:
        secondResultFromApi == secondFeeRecipient

      await client.deleteFeeRecipient(pubkey, correctTokenValue)
      let finalResultFromApi = await client.listFeeRecipient(pubkey, correctTokenValue)
      check:
        finalResultFromApi == defaultFeeRecipient

  suite "Gas limit management" & testFlavour:
    asyncTest "Missing Authorization header" & testFlavour:
      let pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")

      block:
        let
          response = await client.listGasLimitPlain(pubkey)
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.setGasLimitPlain(
            pubkey,
            default SetGasLimitRequest)
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.deleteGasLimitPlain(pubkey, EmptyBody())
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")

      block:
        let
          response = await client.listGasLimitPlain(
            pubkey,
            extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.setGasLimitPlain(
            pubkey,
            default SetGasLimitRequest,
            extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError


      block:
        let
          response = await client.deleteGasLimitPlain(
            pubkey,
            EmptyBody(),
            extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 401
          responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")

      block:
        let
          response = await client.listGasLimitPlain(
            pubkey,
            extraHeaders = @[("Authorization", "Bearer InvalidToken")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 403
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.setGasLimitPlain(
            pubkey,
            default SetGasLimitRequest,
            extraHeaders = @[("Authorization", "Bearer InvalidToken")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 403
          responseJson["message"].getStr() == InvalidAuthorizationError

      block:
        let
          response = await client.deleteGasLimitPlain(
            pubkey,
            EmptyBody(),
            extraHeaders = @[("Authorization", "Bearer InvalidToken")])
          responseJson = Json.decode(response.data, JsonNode)

        check:
          response.status == 403
          responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Obtaining the gas limit of a missing validator returns 404" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(unusedPublicKeys[0]).expect("valid key")
        response = await client.listGasLimitPlain(
          pubkey,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])

      check:
        response.status == 404

    asyncTest "Setting the gas limit on a missing validator creates a record for it" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(unusedPublicKeys[1]).expect("valid key")
        gasLimit = 20_000_000'u64

      await client.setGasLimit(pubkey, gasLimit, correctTokenValue)
      let resultFromApi = await client.listGasLimit(pubkey, correctTokenValue)

      check:
        resultFromApi == gasLimit

    asyncTest "Obtaining the gas limit of an unconfigured validator returns the suggested default" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(oldPublicKeys[0]).expect("valid key")
        resultFromApi = await client.listGasLimit(pubkey, correctTokenValue)

      check:
        resultFromApi == defaultGasLimit

    asyncTest "Configuring the gas limit" & testFlavour:
      let
        pubkey = ValidatorPubKey.fromHex(oldPublicKeys[1]).expect("valid key")
        firstGasLimit = 40_000_000'u64

      await client.setGasLimit(pubkey, firstGasLimit, correctTokenValue)

      let firstResultFromApi = await client.listGasLimit(pubkey, correctTokenValue)
      check:
        firstResultFromApi == firstGasLimit

      let secondGasLimit = 50_000_000'u64
      await client.setGasLimit(pubkey, secondGasLimit, correctTokenValue)

      let secondResultFromApi = await client.listGasLimit(pubkey, correctTokenValue)
      check:
        secondResultFromApi == secondGasLimit

      await client.deleteGasLimit(pubkey, correctTokenValue)
      let finalResultFromApi = await client.listGasLimit(pubkey, correctTokenValue)
      check:
        finalResultFromApi == defaultGasLimit

  suite "ImportRemoteKeys/ListRemoteKeys/DeleteRemoteKeys" & testFlavour:
    asyncTest "Importing list of remote keys" & testFlavour:
      let
        response1 = await client.importRemoteKeysPlain(
          importRemoteKeystoresBody,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson1 = Json.decode(response1.data, JsonNode)

      check:
        response1.status == 200

      for i in 0 ..< 18:
        check:
          responseJson1["data"][i]["status"].getStr() == expectedImportStatus(i)
          responseJson1["data"][i]["message"].getStr() == ""

      let
        filesystemKeys1 = sorted(
          listRemoteValidators(keymanager.validatorsDir,
                               keymanager.secretsDir))
        apiKeystores1 = sorted((
          await client.listRemoteKeys(correctTokenValue)).data)

      check:
        filesystemKeys1 == apiKeystores1

      for item in newPublicKeys:
        let key = ValidatorPubKey.fromHex(item).tryGet()
        let found =
          block:
            var res = false
            for keystore in filesystemKeys1:
              if keystore == key:
                res = true
                break
            res
        check found == true

      let
        response2 = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody2,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson2 = Json.decode(response2.data, JsonNode)

      check:
        response2.status == 200
        responseJson2["data"][0]["status"].getStr() == "deleted"
        responseJson2["data"][1]["status"].getStr() == "deleted"
        responseJson2["data"][2]["status"].getStr() == "deleted"
        responseJson2["data"][3]["status"].getStr() == "deleted"
        responseJson2["data"][4]["status"].getStr() == "deleted"
        responseJson2["data"][5]["status"].getStr() == "deleted"
        responseJson2["data"][6]["status"].getStr() == "deleted"
        responseJson2["data"][7]["status"].getStr() == "deleted"

      let
        filesystemKeys2 = sorted(
          listRemoteValidators(keymanager.validatorsDir,
                               keymanager.secretsDir))
        apiKeystores2 = sorted((
          await client.listRemoteKeys(correctTokenValue)).data)

      check:
        filesystemKeys2 == apiKeystores2

      for keystore in filesystemKeys2:
        let key = "0x" & keystore.toHex()
        check:
          key notin newPublicKeys

    asyncTest "Missing Authorization header" & testFlavour:
      let
        response = await client.importRemoteKeysPlain(importRemoteKeystoresBody)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let
        response = await client.importRemoteKeysPlain(
          importRemoteKeystoresBody,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let
        response = await client.importRemoteKeysPlain(
          importRemoteKeystoresBody,
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 403
        responseJson["message"].getStr() == InvalidAuthorizationError

  suite "DeleteRemoteKeys requests" & testFlavour:
    asyncTest "Deleting not existing key" & testFlavour:
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody3,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 200
        responseJson["data"][0]["status"].getStr() == "not_found"
        responseJson["data"][1]["status"].getStr() == "not_found"

    asyncTest "Deleting existing local key and remote key" & testFlavour:
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody4,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 200
        responseJson["data"][0]["status"].getStr() == "deleted"
        responseJson["data"][1]["status"].getStr() == "deleted"
        responseJson["data"][2]["status"].getStr() == "not_found"
        responseJson["data"][3]["status"].getStr() == "not_found"

      let
        filesystemKeystores = sorted(
          listRemoteValidators(nodeValidatorsDir, nodeSecretsDir))
        apiKeystores = sorted((
          await client.listRemoteKeys(correctTokenValue)).data)

      check:
        filesystemKeystores == apiKeystores

      let
        removedKey0 = ValidatorPubKey.fromHex(oldPublicKeys[0]).tryGet()
        removedKey1 = ValidatorPubKey.fromHex(oldPublicKeys[1]).tryGet()

      for item in apiKeystores:
        check:
          removedKey0 != item.pubkey
          removedKey1 != item.pubkey

    asyncTest "Missing Authorization header" & testFlavour:
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody1)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Header" & testFlavour:
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody1,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["message"].getStr() == InvalidAuthorizationError

    asyncTest "Invalid Authorization Token" & testFlavour:
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody1,
          extraHeaders = @[("Authorization", "Bearer XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 403
        responseJson["message"].getStr() == InvalidAuthorizationError

proc delayedTests(basePort: int) {.async.} =
  let
    beaconNodeKeymanager = KeymanagerToTest(
      ident: "Beacon Node",
      port: basePort + PortKind.KeymanagerBN.ord,
      validatorsDir: nodeValidatorsDir,
      secretsDir: nodeSecretsDir)

    validatorClientKeymanager = KeymanagerToTest(
      ident: "Validator Client",
      port: basePort + PortKind.KeymanagerVC.ord,
      validatorsDir: vcValidatorsDir,
      secretsDir: vcSecretsDir)

  while bnStatus != BeaconNodeStatus.Running:
    await sleepAsync(1.seconds)

  asyncSpawn startValidatorClient(basePort)

  await sleepAsync(2.seconds)

  let deadline = sleepAsync(10.minutes)
  await runTests(beaconNodeKeymanager) or deadline

  # TODO
  # This tests showed flaky behavior on a single Windows CI host
  # Re-enable it in a follow-up PR
  # await runTests(validatorClientKeymanager)

  bnStatus = BeaconNodeStatus.Stopping

proc main(basePort: int) {.async.} =
  if dirExists(dataDir):
    os.removeDir dataDir

  asyncSpawn delayedTests(basePort)

  prepareNetwork()
  startBeaconNode(basePort)

let
  basePortStr = os.getEnv("NIMBUS_TEST_KEYMANAGER_BASE_PORT", $defaultBasePort)
  basePort =
    try:
      let val = parseInt(basePortStr)
      if val < 0 or val > (uint16.high.int - PortKind.high.ord):
        fatal "Invalid base port arg", basePort = basePortStr
        quit 1
      val
    except ValueError as exc:
      fatal "Invalid base port arg", basePort = basePortStr, exc = exc.msg
      quit 1

waitFor main(basePort)
