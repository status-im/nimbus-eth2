import
  ../beacon_chain/[ssz],
  ../beacon_chain/spec/[beaconstate, digest],
  ../tests/testutil

proc stateSize(deposits: int) =
  let state = on_startup(makeInitialDeposits(deposits), 0, Eth2Digest())

  echo "Validators: ", deposits, ", total: ", state.serialize().len

stateSize(1000)
