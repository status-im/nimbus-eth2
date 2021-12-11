{.used.}

import
  std/[typetraits, os, options, json, sequtils, uri, algorithm],
  testutils/unittests, chronicles, stint, json_serialization, confutils,
  chronos, eth/keys, blscurve, libp2p/crypto/crypto as lcrypto,
  stew/[byteutils, io2], stew/shims/net, nimcrypto/utils,

  ../beacon_chain/spec/[crypto, keystore, eth2_merkleization],
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/spec/eth2_apis/[rest_beacon_client, rest_keymanager_types],
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

proc runTests {.async.} =
  while bnStatus != BeaconNodeStatus.Running:
    await sleepAsync(1.seconds)

  await sleepAsync(2.seconds)

  let
    client = RestClientRef.new(initTAddress("127.0.0.1", keymanagerPort))
    rng = keys.newRng()
    privateKey = ValidatorPrivKey.fromRaw(secretBytes).get

    newKeystore = createKeystore(
      kdfPbkdf2, rng[], privateKey,
      KeystorePass.init password,
      salt = salt, iv = iv,
      description = "This is a test keystore that uses PBKDF2 to secure the secret",
      path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))

    importKeystoresBody = KeystoresAndSlashingProtection(
      keystores: @[newKeystore],
      passwords: @[password],
      slashing_protection: SPDIR())

    deleteKeysBody = DeleteKeystoresBody(
      pubkeys: @[privateKey.toPubKey.toPubKey])

  suite "ListKeys requests" & preset():
    asyncTest "Correct token provided" & preset():
      let
        filesystemKeystores = sorted(listValidators(validatorsDir, secretsDir))
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

  bnStatus = BeaconNodeStatus.Stopping

proc main() {.async.} =
  asyncSpawn runTests()
  startSingleNodeNetwork()
