import
  chronos,
  "."/[beacon_clock, beacon_chain_db, conf],
  ./el/el_manager,
  ./spec/forks,
  ./validators/[
    message_router, validator_pool,
    keystore_management]

import "."/consensus_object_pools/block_dag

export
  chronos,
  beacon_clock, beacon_chain_db, conf,
  el_manager,
  forks,
  base, message_router, validator_pool

type
  BeaconNode* = ref object
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ref ValidatorPool
    elManager*: ELManager
    keystoreCache*: KeystoreCacheRef
    genesisSnapshotContent*: string
    beaconClock*: BeaconClock
    router*: ref MessageRouter
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

proc getProposalState*(
    node: BeaconNode, head: BlockRef, slot: Slot, cache: var StateCache):
    Result[ref ForkedHashedBeaconState, cstring] =
  let state = assignClone(node.genesisState[])
  ok state
