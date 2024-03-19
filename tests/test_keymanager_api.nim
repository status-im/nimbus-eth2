import
  std/os,
  confutils,
  chronos,
  ../beacon_chain/[
    conf,
    filepath,
    beacon_node,
    nimbus_beacon_node,
    ]

const
  dataDir = "./test_keymanager_api"
  nodeDataDir = dataDir / "node-0"
  nodeValidatorsDir = nodeDataDir / "validators"
  nodeSecretsDir = nodeDataDir / "secrets"

proc startBeaconNode() {.raises: [CatchableError].} =
  let runNodeConf = try: BeaconNodeConf.load(cmdLine = @[
    "--network=" & dataDir,
    "--data-dir=" & nodeDataDir])
  except Exception as exc: # TODO fix confutils exceptions
    raiseAssert exc.msg

  let
    metadata = loadEth2NetworkMetadata(dataDir).expect("Metadata is compatible")
    node = waitFor BeaconNode.init(runNodeConf, metadata)

  node.start()

startBeaconNode()
