import
  "."/[beacon_clock, conf],
  ./el/el_manager,
  ./spec/forks,
  ./validators/[
    message_router]

export
  beacon_clock, conf,
  forks,
  message_router

type
  BeaconNode* = ref object
    elManager*: ELManager
    beaconClock*: BeaconClock
    cfg*: RuntimeConfig
    genesisState*: ref ForkedHashedBeaconState

proc currentSlot*(node: BeaconNode): uint64 =
  node.beaconClock.now.slotOrZero
