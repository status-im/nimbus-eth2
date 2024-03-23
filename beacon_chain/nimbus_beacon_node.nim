import
  chronos,
  ./validators/beacon_validators

type
  BeaconTime = object
    ns_since_genesis: int64

  TimeDiff = object
    nanoseconds: int64

const
  FAR_FUTURE_BEACON_TIME = BeaconTime(ns_since_genesis: int64.high())
  NANOSECONDS_PER_SLOT = 12 * 1_000_000_000'u64

func toSlot(t: BeaconTime): tuple[afterGenesis: bool, slot: uint64] =
  if t == FAR_FUTURE_BEACON_TIME:
    (true, (not 0'u64))
  elif t.ns_since_genesis >= 0:
    (true, uint64(uint64(t.ns_since_genesis) div NANOSECONDS_PER_SLOT))
  else:
    (false, uint64(uint64(-t.ns_since_genesis) div NANOSECONDS_PER_SLOT))

template `-`(t: BeaconTime, offset: TimeDiff): BeaconTime =
  BeaconTime(ns_since_genesis: t.ns_since_genesis - offset.nanoseconds)

template `-`(a, b: BeaconTime): TimeDiff =
  TimeDiff(nanoseconds: a.ns_since_genesis - b.ns_since_genesis)
func start_beacon_time(s: uint64): BeaconTime =
  const maxSlot = uint64(
    uint64(FAR_FUTURE_BEACON_TIME.ns_since_genesis) div NANOSECONDS_PER_SLOT)
  if s > maxSlot: FAR_FUTURE_BEACON_TIME
  else: BeaconTime(ns_since_genesis: int64(uint64(s) * NANOSECONDS_PER_SLOT))

func slotOrZero(time: BeaconTime): uint64 =
  let exSlot = time.toSlot
  if exSlot.afterGenesis: exSlot.slot
  else: uint64(0)

from std/times import Time, getTime, `-`, inNanoseconds

type
  BeaconClock = object
    genesis: Time

func toBeaconTime(c: BeaconClock, t: Time): BeaconTime =
  BeaconTime(ns_since_genesis: inNanoseconds(t - c.genesis))

proc now(c: BeaconClock): BeaconTime =
  toBeaconTime(c, getTime())

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

type
  RuntimeConfig = object
  BeaconNode = ref object
    beaconClock: BeaconClock
    cfg: RuntimeConfig

proc init(T: type BeaconNode,
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
  proc startBeaconNode() {.raises: [CatchableError].} =
    let
      cfg = RuntimeConfig()
      node = waitFor BeaconNode.init(cfg)
  
    node.start()
  
  startBeaconNode()
