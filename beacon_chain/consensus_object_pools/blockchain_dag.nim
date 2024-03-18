import
  ../spec/[beaconstate, helpers],
  ../spec/forks,
  "."/block_pools_types

proc putBlock(
    dag: ChainDAGRef, signedBlock: ForkyTrustedSignedBeaconBlock) =
  dag.db.putBlock(signedBlock)

proc preInit*(
    T: type ChainDAGRef, state: ForkedHashedBeaconState) =
  doAssert getStateField(state, slot).is_epoch,
    "Can only initialize database from epoch states"

  withState(state):
    if forkyState.data.slot == GENESIS_SLOT:
      let blck = get_initial_beacon_block(forkyState)
    else:
      let blockRoot = forkyState.latest_block_root()
