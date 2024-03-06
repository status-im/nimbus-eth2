import
  std/os,
  testutils/unittests, chronicles, stint, json_serialization, confutils,
  chronos, blscurve, libp2p/crypto/crypto as lcrypto,
  stew/[byteutils, io2],

  ../beacon_chain/spec/[crypto, keystore, eth2_merkleization],
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/validators/[keystore_management, slashing_protection_common],
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/[conf, filepath, beacon_node,
                   nimbus_beacon_node, beacon_node_status,
                   nimbus_validator_client],
  ../beacon_chain/validator_client/common,
  ../ncli/ncli_testnet

type
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

  nodeDataDir = dataDir / "node-0"
  nodeValidatorsDir = nodeDataDir / "validators"
  nodeSecretsDir = nodeDataDir / "secrets"

  vcDataDir = dataDir / "validator-0"
  vcValidatorsDir = vcDataDir / "validators"
  vcSecretsDir = vcDataDir / "secrets"

proc prepareNetwork =
  let
    rng = HmacDrbgContext.new()
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

proc startBeaconNode(basePort: int) {.raises: [CatchableError].} =
  let rng = HmacDrbgContext.new()

  copyHalfValidators(nodeDataDir, true)

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
    "--doppelganger-detection=off",
    "--debug-forkchoice-version=stable"], it))
  except Exception as exc: # TODO fix confutils exceptions
    raiseAssert exc.msg

  let
    metadata = loadEth2NetworkMetadata(dataDir).expect("Metadata is compatible")
    node = waitFor BeaconNode.init(rng, runNodeConf, metadata)

  node.start() # This will run until the node is terminated by
               #  setting its `bnStatus` to `Stopping`.


proc startValidatorClient(basePort: int) {.async, thread.} =
  let rng = HmacDrbgContext.new()

  copyHalfValidators(vcDataDir, false)

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
  secretBytes = hexToSeqByte "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
  salt = hexToSeqByte "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
  iv = hexToSeqByte "264daa3f303d7259501c93d997d84fe6"

proc runTests() {.async.} =
  let
    rng = HmacDrbgContext.new()
    privateKey = ValidatorPrivKey.fromRaw(secretBytes).get

  discard createKeystore(
    kdfPbkdf2, rng[], privateKey,
    KeystorePass.init password,
    salt = salt, iv = iv,
    description = "This is a test keystore that uses PBKDF2 to secure the secret",
    path = validateKeyPath("m/12381/60/0/0").expect("Valid Keypath"))

  await sleepAsync(8.seconds)

proc delayedTests(basePort: int) {.async.} =
  while bnStatus != BeaconNodeStatus.Running:
    await sleepAsync(1.seconds)

  asyncSpawn startValidatorClient(basePort)

  await sleepAsync(2.seconds)
  await runTests()

  bnStatus = BeaconNodeStatus.Stopping

proc main(basePort: int) {.async.} =
  if dirExists(dataDir):
    os.removeDir dataDir

  asyncSpawn delayedTests(basePort)

  prepareNetwork()
  startBeaconNode(basePort)

waitFor main(defaultBasePort)
