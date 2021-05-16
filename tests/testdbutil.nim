# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  ../beacon_chain/[beacon_chain_db, extras],
  ../beacon_chain/consensus_object_pools/blockchain_dag,
  ../beacon_chain/spec/[beaconstate, digest],
  eth/db/[kvstore, kvstore_sqlite3],
  ./testblockutil

export beacon_chain_db, testblockutil, kvstore, kvstore_sqlite3

proc makeTestDB*(tailState: var BeaconState, tailBlock: SignedBeaconBlock): BeaconChainDB =
  result = BeaconChainDB.new(defaultRuntimePreset, "", inMemory = true)
  ChainDAGRef.preInit(result, tailState, tailState, tailBlock)

proc makeTestDB*(validators: Natural): BeaconChainDB =
  let
    genState = initialize_beacon_state_from_eth1(
      defaultRuntimePreset,
      Eth2Digest(),
      0,
      makeInitialDeposits(validators.uint64, flags = {skipBlsValidation}),
      {skipBlsValidation})
    genBlock = get_initial_beacon_block(genState[])
  makeTestDB(genState[], genBlock)
