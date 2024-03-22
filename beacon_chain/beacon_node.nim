import
  chronos,
  "."/[beacon_clock, conf],
  ./el/el_manager,
  ./spec/forks,
  ./validators/[
    message_router]

import "."/consensus_object_pools/block_dag

export
  chronos,
  beacon_clock, conf,
  el_manager,
  forks,
  message_router

type
  BeaconNode* = ref object
    config*: BeaconNodeConf
    elManager*: ELManager
    genesisSnapshotContent*: string
    beaconClock*: BeaconClock
    cfg*: RuntimeConfig
    genesisState*: ref ForkedHashedBeaconState

template findIt*(s: openArray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

proc currentSlot*(node: BeaconNode): Slot =
  node.beaconClock.now.slotOrZero
