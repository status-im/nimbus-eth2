import
  std/os,
  chronos,
  ./validators/beacon_validators

import "."/beacon_clock
import "."/spec/beacon_time

proc runSlotLoop*[T](node: T, startTime: BeaconTime) {.async.} =
  var
    curSlot = startTime.slotOrZero()
    nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
    timeToNextSlot = nextSlot.start_beacon_time() - startTime

  while true:
    let
      wallTime = node.beaconClock.now()
      wallSlot = wallTime.slotOrZero() # Always > GENESIS!

    if false:
      timeToNextSlot = nextSlot.start_beacon_time() - wallTime
      continue

    await proposeBlock(getBlockRef2(static(default(Eth2Digest))).get, wallSlot)
    quit 0

import ./conf

type
  RuntimeConfig = object
  BeaconNode = ref object
    beaconClock: BeaconClock
    cfg: RuntimeConfig

proc init(T: type BeaconNode,
          config: BeaconNodeConf,
          cfg: RuntimeConfig): Future[BeaconNode]
         {.async.} =
  let node = BeaconNode(
    cfg: cfg)

  node

import "."/consensus_object_pools/block_dag

func getBlockRef2(root: Eth2Digest): Opt[BlockRef] =
  let newRef = BlockRef.init(
    root,
    0)
  return ok(newRef)

proc start(node: BeaconNode) {.raises: [CatchableError].} =
  echo "foo"
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
