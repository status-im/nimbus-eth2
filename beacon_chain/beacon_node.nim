import
  std/osproc,

  # Nimble packages
  chronos, bearssl/rand,

  # Local modules
  "."/[beacon_clock, beacon_chain_db, conf],
  ./el/el_manager,
  ./consensus_object_pools/blockchain_dag,
  ./spec/datatypes/[base, altair],
  ./validators/[
    message_router, validator_pool,
    keystore_management]

export
  osproc, chronos,
  beacon_clock, beacon_chain_db, conf,
  el_manager,
  blockchain_dag,
  base, message_router, validator_pool

type
  BeaconNode* = ref object
    nickname*: string
    db*: BeaconChainDB
    config*: BeaconNodeConf
    attachedValidators*: ref ValidatorPool
    dag*: ChainDAGRef
    elManager*: ELManager
    keystoreCache*: KeystoreCacheRef
    vcProcess*: Process
    genesisSnapshotContent*: string
    attachedValidatorBalanceTotal*: uint64
    beaconClock*: BeaconClock
    router*: ref MessageRouter
    dutyValidatorCount*: int

const
  MaxEmptySlotCount* = uint64(10*60) div SECONDS_PER_SLOT

# TODO stew/sequtils2
template findIt*(s: openArray, predicate: untyped): int =
  var res = -1
  for i, it {.inject.} in s:
    if predicate:
      res = i
      break
  res

template rng*(node: BeaconNode): ref HmacDrbgContext =
  node.network.rng

proc currentSlot*(node: BeaconNode): Slot =
  node.beaconClock.now.slotOrZero

func getPayloadBuilderAddress*(config: BeaconNodeConf): Opt[string] =
  if config.payloadBuilderEnable:
    Opt.some config.payloadBuilderUrl
  else:
    Opt.none(string)

proc getPayloadBuilderAddress*(
    node: BeaconNode, pubkey: ValidatorPubKey): Opt[string] =
  node.config.getPayloadBuilderAddress
