import
  ../beacon_chain/[extras, ssz],
  ../beacon_chain/spec/[beaconstate, datatypes, digest],
  ../tests/testutil,
  cligen

proc stateSize(deposits: int, maxContent = false) =
  var state = get_initial_beacon_state(
    makeInitialDeposits(deposits), 0, Eth2Digest(), {skipValidation})

  if maxContent:
    # TODO verify this is correct, but generally we collect up to two epochs
    #      of attestations, and each block has a cap on the number of
    #      attestations it may hold, so we'll just add so many of them
    state.latest_attestations.setLen(MAX_ATTESTATIONS * EPOCH_LENGTH * 2)
    let validatorsPerCommittee =
      len(state.shard_committees_at_slots[0][0].committee) # close enough..
    for a in state.latest_attestations.mitems():
      a.participation_bitfield.setLen(validatorsPerCommittee)
  echo "Validators: ", deposits, ", total: ", state.serialize().len

dispatch(stateSize)
