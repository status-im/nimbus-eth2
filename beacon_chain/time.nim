import
  random,
  asyncdispatch2,
  spec/datatypes

type
  Timestamp* = uint64 # Unix epoch timestamp in millisecond resolution

var
  detectedClockDrift: int64

template now*: auto = fastEpochTime()

proc timeSinceGenesis*(s: BeaconState): Timestamp =
  Timestamp(int64(fastEpochTime() - s.genesis_time * 1000) -
            detectedClockDrift)

template toSlot*(t: Timestamp): int =
  int(t div uint64(SLOT_DURATION * 1000))

template slotStart*(s: BeaconState, slot: int): Timestamp =
  (s.genesis_time + uint64(slot * SLOT_DURATION)) * 1000

template slotMiddle*(s: BeaconState, slot: int): Timestamp =
  s.slotStart(slot) + SLOT_DURATION * 500

template slotEnd*(s: BeaconState, slot: int): Timestamp =
  s.slotStart(slot + 1)

proc randomTimeInSlot*(s: BeaconState,
                       slot: Natural,
                       interval: HSlice[float, float]): Timestamp =
  ## Returns a random moment within the slot.
  ## The interval must be a sub-interval of [0..1].
  ## Zero marks the begginning of the slot and One marks the end.
  s.slotStart(slot) + Timestamp(rand(interval) * float(SLOT_DURATION * 1000))

proc slotDistanceFromNow*(s: BeaconState): int64 =
  ## Returns how many slots have passed since a particular BeaconState was finalized
  int64(s.timeSinceGenesis() div (SLOT_DURATION * 1000)) - int64(s.finalized_slot)

proc syncrhronizeClock*() {.async.} =
  ## This should determine the offset of the local clock against a global
  ## trusted time (e.g. it can be obtained from multiple time servers).

  # TODO: implement this properly
  detectedClockDrift = 0

