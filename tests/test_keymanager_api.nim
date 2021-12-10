{.used.}

import
  std/[typetraits, os, options, json, sequtils, uri, algorithm],
  testutils/unittests, chronicles, stint, json_serialization, confutils,
  chronos, eth/keys, blscurve, libp2p/crypto/crypto as lcrypto,
  stew/[byteutils, io2], stew/shims/net, nimcrypto/utils,

  ../beacon_chain/spec/[crypto, keystore, eth2_merkleization],
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/eth2_apis/[rest_keymanager_calls, rest_keymanager_types],
  ../beacon_chain/validators/[keystore_management, slashing_protection_common],
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/rpc/rest_key_management_api,
  ../beacon_chain/[conf, filepath, beacon_node,
                   nimbus_beacon_node, beacon_node_status],

  ./testutil

const
  simulationDepositsCount = 128
  dataDir = "./test_keymanager_api"
  validatorsDir = dataDir / "validators"
  secretsDir = dataDir / "secrets"
  depositsFile = dataDir / "deposits.json"
  genesisFile = dataDir / "genesis.ssz"
  bootstrapEnrFile = dataDir / "bootstrap_node.enr"
  tokenFilePath = dataDir / "keymanager-token.txt"
  keymanagerPort = 47000
  correctTokenValue = "some secret token"
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
  newPublicKeysUrl = HttpHostUri(parseUri("http://127.0.0.1/remote"))

proc contains*(keylist: openArray[KeystoreInfo], key: ValidatorPubKey): bool =
  for item in keylist:
    if item.validating_pubkey == key:
      return true
  false

proc contains*(keylist: openArray[KeystoreInfo], key: string): bool =
  let pubkey = ValidatorPubKey.fromHex(key).tryGet()
  contains(keylist, pubkey)

proc startSingleNodeNetwork =
  let
    rng = keys.newRng()
    mnemonic = generateMnemonic(rng[])
    seed = getSeed(mnemonic, KeyStorePass.init "")
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
    KeystoreMode.Fast)

  if deposits.isErr:
    fatal "Failed to generate deposits", err = deposits.error
    quit 1

  let launchPadDeposits =
    mapIt(deposits.value, LaunchPadDeposit.init(cfg, it))

  Json.saveFile(depositsFile, launchPadDeposits)
  notice "Deposit data written", filename = depositsFile

  for item in oldPublicKeys:
    let key = ValidatorPubKey.fromHex(item).tryGet()
    let res = saveKeystore(validatorsDir, key, oldPublicKeysUrl)
    if res.isErr():
      fatal "Failed to create remote keystore file", err = res.error
      quit 1

  let tokenFileRes = secureWriteFile(tokenFilePath, correctTokenValue)
  if tokenFileRes.isErr:
    fatal "Failed to create token file", err = deposits.error
    quit 1

  let createTestnetConf = BeaconNodeConf.load(cmdLine = mapIt([
    "--data-dir=" & dataDir,
    "createTestnet",
    "--total-validators=" & $simulationDepositsCount,
    "--deposits-file=" & depositsFile,
    "--output-genesis=" & genesisFile,
    "--output-bootstrap-file=" & bootstrapEnrFile,
    "--netkey-file=network_key.json",
    "--insecure-netkey-password=true",
    "--genesis-offset=0"], TaintedString it))

  doCreateTestnet(createTestnetConf, rng[])

  let runNodeConf = BeaconNodeConf.load(cmdLine = mapIt([
    "--tcp-port=49000",
    "--udp-port=49000",
    "--network=" & dataDir,
    "--data-dir=" & dataDir,
    "--validators-dir=" & validatorsDir,
    "--secrets-dir=" & secretsDir,
    "--metrics-address=127.0.0.1",
    "--metrics-port=48008",
    "--rest-address=127.0.0.1",
    "--rest-port=" & $keymanagerPort,
    "--keymanager=true",
    "--keymanager-address=127.0.0.1",
    "--keymanager-port=" & $keymanagerPort,
    "--keymanager-token-file=" & tokenFilePath,
    "--doppelganger-detection=off"], TaintedString it))

  let metadata = loadEth2NetworkMetadata(dataDir, none(Eth1Network))

  let node = BeaconNode.init(
    metadata.cfg,
    rng,
    runNodeConf,
    metadata.depositContractDeployedAt,
    metadata.eth1Network,
    metadata.genesisData,
    metadata.genesisDepositsSnapshot
  )

  node.start() # This will run until the node is terminated by
               # setting its `bnStatus` to `Stopping`.

  os.removeDir dataDir

const
  password = "7465737470617373776f7264f09f9491"
  # This is taken from the offical test vectors in test_keystores.nim
  secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
  iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"
  secretNetBytes = hexToSeqByte "08021220fe442379443d6e2d7d75d3a58f96fbb35f0a9c7217796825fc9040e3b89c5736"

proc listLocalValidators(validatorsDir,
                         secretsDir: string): seq[KeystoreInfo] {.
     raises: [Defect].} =
  var validators: seq[KeystoreInfo]

  try:
    for el in listLoadableKeystores(validatorsDir, secretsDir, true,
                                    {KeystoreKind.Local}):
      validators.add KeystoreInfo(validating_pubkey: el.pubkey,
                                  derivation_path: el.path.string,
                                  readonly: false)
  except OSError as err:
    error "Failure to list the validator directories",
          validatorsDir, secretsDir, err = err.msg

  validators

proc listRemoteValidators(validatorsDir,
                          secretsDir: string): seq[RemoteKeystoreInfo] {.
     raises: [Defect].} =
  var validators: seq[RemoteKeystoreInfo]

  try:
    for el in listLoadableKeystores(validatorsDir, secretsDir, true,
                                    {KeystoreKind.Remote}):
      validators.add RemoteKeystoreInfo(pubkey: el.pubkey,
                                        url: el.remoteUrl)

  except OSError as err:
    error "Failure to list the validator directories",
          validatorsDir, secretsDir, err = err.msg

  validators

proc runTests {.async.} =
  while bnStatus != BeaconNodeStatus.Running:
    await sleepAsync(1.seconds)

  await sleepAsync(2.seconds)

  let
    client = RestClientRef.new(initTAddress("127.0.0.1", keymanagerPort))
    rng = keys.newRng()
    privateKey = ValidatorPrivKey.fromRaw(secretBytes).get

    localList = listLocalValidators(validatorsDir, secretsDir)

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
        res.add(RemoteKeystoreInfo(pubkey: localList[0].validating_pubkey,
                                   url: newPublicKeysUrl))
        res.add(RemoteKeystoreInfo(pubkey: localList[1].validating_pubkey,
                                   url: newPublicKeysUrl))
        ImportRemoteKeystoresBody(remote_keys: res)

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
            localList[0].validating_pubkey,
            localList[1].validating_pubkey
          ]
        )

  suite "ListKeys requests" & preset():
    asyncTest "Correct token provided" & preset():
      let
        filesystemKeystores = sorted(
          listLocalValidators(validatorsDir, secretsDir))
        apiKeystores = sorted((await client.listKeys(correctTokenValue)).data)

      check filesystemKeystores == apiKeystores

    asyncTest "Missing Authorization header" & preset():
      let
        response = await client.listKeysPlain()
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $noAuthorizationHeader

    asyncTest "Invalid Authorization Header" & preset():
      let
        response = await client.listKeysPlain(
          extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $missingBearerScheme

    asyncTest "Invalid Authorization Token" & preset():
      let
        response = await client.listKeysPlain(
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $incorrectToken

      expect RestError:
        let keystores = await client.listKeys("Invalid Token")

  suite "ImportKeystores requests" & preset():
    asyncTest "ImportKeystores/ListKeystores/DeleteKeystores" & preset():
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
        filesystemKeystores1 = sorted(
          listLocalValidators(validatorsDir, secretsDir))
        apiKeystores1 = sorted((await client.listKeys(correctTokenValue)).data)

      check:
        filesystemKeystores1 == apiKeystores1
        importKeystoresBody1.keystores[0].pubkey in filesystemKeystores1
        importKeystoresBody1.keystores[1].pubkey in filesystemKeystores1
        importKeystoresBody1.keystores[2].pubkey in filesystemKeystores1
        importKeystoresBody1.keystores[3].pubkey in filesystemKeystores1
        importKeystoresBody1.keystores[4].pubkey in filesystemKeystores1
        importKeystoresBody1.keystores[5].pubkey in filesystemKeystores1
        importKeystoresBody1.keystores[6].pubkey in filesystemKeystores1
        importKeystoresBody1.keystores[7].pubkey in filesystemKeystores1

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
        filesystemKeystores2 = sorted(
          listLocalValidators(validatorsDir, secretsDir))
        apiKeystores2 = sorted((await client.listKeys(correctTokenValue)).data)

      check:
        filesystemKeystores2 == apiKeystores2
        deleteKeysBody1.pubkeys[0] notin filesystemKeystores2
        deleteKeysBody1.pubkeys[1] notin filesystemKeystores2
        deleteKeysBody1.pubkeys[2] notin filesystemKeystores2
        deleteKeysBody1.pubkeys[3] notin filesystemKeystores2
        deleteKeysBody1.pubkeys[4] notin filesystemKeystores2
        deleteKeysBody1.pubkeys[5] notin filesystemKeystores2
        deleteKeysBody1.pubkeys[6] notin filesystemKeystores2
        deleteKeysBody1.pubkeys[7] notin filesystemKeystores2

    asyncTest "Missing Authorization header" & preset():
      let
        response = await client.importKeystoresPlain(importKeystoresBody)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $noAuthorizationHeader

    asyncTest "Invalid Authorization Header" & preset():
      let
        response = await client.importKeystoresPlain(
          importKeystoresBody,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $missingBearerScheme

    asyncTest "Invalid Authorization Token" & preset():
      let
        response = await client.importKeystoresPlain(
          importKeystoresBody,
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $incorrectToken

  suite "DeleteKeys requests" & preset():
    asyncTest "Deleting not existing key" & preset():
      let
        response = await client.deleteKeysPlain(
          deleteKeysBody,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 200
        responseJson["data"][0]["status"].getStr() == "not_found"
        responseJson["data"][0]["message"].getStr() == ""

    asyncTest "Missing Authorization header" & preset():
      let
        response = await client.deleteKeysPlain(deleteKeysBody)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $noAuthorizationHeader

    asyncTest "Invalid Authorization Header" & preset():
      let
        response = await client.deleteKeysPlain(
          deleteKeysBody,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $missingBearerScheme

    asyncTest "Invalid Authorization Token" & preset():
      let
        response = await client.deleteKeysPlain(
          deleteKeysBody,
          extraHeaders = @[("Authorization", "Bearer XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $incorrectToken

  suite "ListRemoteKeys requests" & preset():
    asyncTest "Correct token provided" & preset():
      let
        filesystemKeystores = sorted(
          listRemoteValidators(validatorsDir, secretsDir))
        apiKeystores = sorted((
          await client.listRemoteKeys(correctTokenValue)).data)

      check filesystemKeystores == apiKeystores

    asyncTest "Missing Authorization header" & preset():
      let
        response = await client.listRemoteKeysPlain()
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $noAuthorizationHeader

    asyncTest "Invalid Authorization Header" & preset():
      let
        response = await client.listRemoteKeysPlain(
          extraHeaders = @[("Authorization", "UnknownAuthScheme X")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $missingBearerScheme

    asyncTest "Invalid Authorization Token" & preset():
      let
        response = await client.listRemoteKeysPlain(
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $incorrectToken

      expect RestError:
        let keystores = await client.listKeys("Invalid Token")

  suite "ImportRemoteKeys/ListRemoteKeys/DeleteRemoteKeys" & preset():
    asyncTest "Importing list of remote keys" & preset():
      let
        response1 = await client.importRemoteKeysPlain(
          importRemoteKeystoresBody,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson1 = Json.decode(response1.data, JsonNode)

      check:
        response1.status == 200
      for i in [0, 1, 2, 3, 4, 5, 6, 7, 16, 17]:
        check:
          responseJson1["data"][i]["status"].getStr() == "duplicate"
          responseJson1["data"][i]["message"].getStr() == ""
      for i in 8 ..< 16:
        check:
          responseJson1["data"][i]["status"].getStr() == "imported"
          responseJson1["data"][i]["message"].getStr() == ""

      let
        filesystemKeystores1 = sorted(
          listRemoteValidators(validatorsDir, secretsDir))
        apiKeystores1 = sorted((
          await client.listRemoteKeys(correctTokenValue)).data)

      check:
        filesystemKeystores1 == apiKeystores1

      for item in newPublicKeys:
        let key = ValidatorPubKey.fromHex(item).tryGet()
        let found =
          block:
            var res = false
            for keystore in filesystemKeystores1:
              if keystore.pubkey == key:
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
        filesystemKeystores2 = sorted(
          listRemoteValidators(validatorsDir, secretsDir))
        apiKeystores2 = sorted((
          await client.listRemoteKeys(correctTokenValue)).data)

      check:
        filesystemKeystores2 == apiKeystores2

      for keystore in filesystemKeystores2:
        let key = "0x" & keystore.pubkey.toHex()
        check:
          key notin newPublicKeys

    asyncTest "Missing Authorization header" & preset():
      let
        response = await client.importRemoteKeysPlain(importRemoteKeystoresBody)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $noAuthorizationHeader

    asyncTest "Invalid Authorization Header" & preset():
      let
        response = await client.importRemoteKeysPlain(
          importRemoteKeystoresBody,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $missingBearerScheme

    asyncTest "Invalid Authorization Token" & preset():
      let
        response = await client.importRemoteKeysPlain(
          importRemoteKeystoresBody,
          extraHeaders = @[("Authorization", "Bearer InvalidToken")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $incorrectToken

  suite "DeleteRemoteKeys requests" & preset():
    asyncTest "Deleting not existing key" & preset():
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody3,
          extraHeaders = @[("Authorization", "Bearer " & correctTokenValue)])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 200
        responseJson["data"][0]["status"].getStr() == "not_found"
        responseJson["data"][1]["status"].getStr() == "not_found"

    asyncTest "Deleting existing local key and remote key" & preset():
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
          listRemoteValidators(validatorsDir, secretsDir))
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

    asyncTest "Missing Authorization header" & preset():
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody1)
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $noAuthorizationHeader

    asyncTest "Invalid Authorization Header" & preset():
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody1,
          extraHeaders = @[("Authorization", "Basic XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $missingBearerScheme

    asyncTest "Invalid Authorization Token" & preset():
      let
        response = await client.deleteRemoteKeysPlain(
          deleteRemoteKeystoresBody1,
          extraHeaders = @[("Authorization", "Bearer XYZ")])
        responseJson = Json.decode(response.data, JsonNode)

      check:
        response.status == 401
        responseJson["code"].getStr() == "401"
        responseJson["message"].getStr() == InvalidAuthorization
        responseJson["stacktraces"][0].getStr() == $incorrectToken

  bnStatus = BeaconNodeStatus.Stopping

proc main() {.async.} =
  asyncSpawn runTests()
  startSingleNodeNetwork()
