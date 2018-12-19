import
  ../beacon_chain/[ssz],
  ../beacon_chain/spec/[beaconstate, digest],
  ../tests/testutil

proc stateSize(deposits: int) =
  let state = get_initial_beacon_state(
    makeInitialDeposits(deposits), 0, Eth2Digest())

  echo "Validators: ", deposits, ", total: ", state.serialize().len

stateSize(1000)
