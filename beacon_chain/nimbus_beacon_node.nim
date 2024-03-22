import
  std/os,
  chronos,
  stew/io2,
  ./spec/datatypes/[altair, bellatrix, phase0],
  ./validators/beacon_validators,
  "."/[
    beacon_node,
    nimbus_binary_common]

from ./spec/datatypes/deneb import SignedBeaconBlock

proc init(T: type BeaconNode,
          config: BeaconNodeConf,
          metadata: Eth2NetworkMetadata): Future[BeaconNode]
         {.async.} =
  template cfg: auto = metadata.cfg

  let node = BeaconNode(
    cfg: cfg)

  node

from "."/consensus_object_pools/block_dag import BlockRef, init

func getBlockRef2(root: Eth2Digest): Opt[BlockRef] =
  let newRef = BlockRef.init(
    root,
    0.Slot)
  return ok(newRef)

import "."/el/el_manager

proc start(node: BeaconNode) {.raises: [CatchableError].} =
  echo "foo"
  let elManager = default(ELManager)
  elManager.start()
  let
    wallTime = node.beaconClock.now()

  asyncSpawn runSlotLoop(node, wallTime)

  while true:
    poll()

when isMainModule:
  import
    confutils,
    ../beacon_chain/conf
  const
    dataDir = "./test_keymanager_api"
    nodeDataDir = dataDir / "node-0"
    nodeValidatorsDir = nodeDataDir / "validators"
    nodeSecretsDir = nodeDataDir / "secrets"

  proc startBeaconNode() {.raises: [CatchableError].} =
    #copyHalfValidators(nodeDataDir, true)
  
    let runNodeConf = try: BeaconNodeConf.load(cmdLine = @[
      "--network=" & dataDir,
      "--data-dir=" & nodeDataDir,
      "--validators-dir=" & nodeValidatorsDir,
      "--secrets-dir=" & nodeSecretsDir,
      "--no-el"])
    except Exception as exc: # TODO fix confutils exceptions
      raiseAssert exc.msg
  
    let
      metadata = loadEth2NetworkMetadata(dataDir).expect("Metadata is compatible")
      node = waitFor BeaconNode.init(runNodeConf, metadata)
  
    node.start()
  
  startBeaconNode()
