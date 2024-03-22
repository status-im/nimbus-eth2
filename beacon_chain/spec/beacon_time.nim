import
  chronos/timer

type
  BeaconTime* = object
    ns_since_genesis*: int64

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

template `-`(t: BeaconTime, offset: Duration | TimeDiff): BeaconTime =
  BeaconTime(ns_since_genesis: t.ns_since_genesis - offset.nanoseconds)

template `-`*(a, b: BeaconTime): TimeDiff =
  TimeDiff(nanoseconds: a.ns_since_genesis - b.ns_since_genesis)
func start_beacon_time*(s: uint64): BeaconTime =
  const maxSlot = uint64(
    uint64(FAR_FUTURE_BEACON_TIME.ns_since_genesis) div NANOSECONDS_PER_SLOT)
  if s > maxSlot: FAR_FUTURE_BEACON_TIME
  else: BeaconTime(ns_since_genesis: int64(uint64(s) * NANOSECONDS_PER_SLOT))

func slotOrZero*(time: BeaconTime): uint64 =
  let exSlot = time.toSlot
  if exSlot.afterGenesis: exSlot.slot
  else: uint64(0)
