import
  std/os,
  chronos,
  stew/io2,
  ./validators/beacon_validators,
  "."/nimbus_binary_common

import
  "."/[beacon_clock, conf],
  ./spec/forks

type
  RuntimeConfig = object
  BeaconNode = ref object
    beaconClock: BeaconClock
    cfg: RuntimeConfig
    genesisState: ref ForkedHashedBeaconState

proc init(T: type BeaconNode,
          config: BeaconNodeConf,
          cfg: RuntimeConfig): Future[BeaconNode]
         {.async.} =
  let node = BeaconNode(
    cfg: cfg)

  node

from "."/consensus_object_pools/block_dag import BlockRef, init
import "."/spec/digest

func getBlockRef2(root: Eth2Digest): Opt[BlockRef] =
  let newRef = BlockRef.init(
    root,
    0)
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
    confutils
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
      cfg = RuntimeConfig()
      node = waitFor BeaconNode.init(runNodeConf, cfg)
  
    node.start()
  
  startBeaconNode()
