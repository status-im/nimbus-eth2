# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  chronicles,
  ../beacon_chain/[beacon_chain_db],
  ../beacon_chain/consensus_object_pools/blockchain_dag,
  ../beacon_chain/spec/datatypes/phase0,
  ../beacon_chain/spec/[beaconstate, forks],
  eth/db/[kvstore, kvstore_sqlite3],
  ./testblockutil

export beacon_chain_db, testblockutil, kvstore, kvstore_sqlite3

proc makeTestDB*(
    validators: Natural, cfg = defaultRuntimeConfig): BeaconChainDB =
  let
    genState = (ref ForkedHashedBeaconState)(
      kind: ConsensusFork.Phase0,
      phase0Data: initialize_hashed_beacon_state_from_eth1(
        cfg,
        ZERO_HASH,
        0,
        makeInitialDeposits(validators.uint64, flags = {skipBlsValidation}),
        {skipBlsValidation}))

  result = BeaconChainDB.new("", cfg = cfg, inMemory = true)
  ChainDAGRef.preInit(result, genState[])

proc getEarliestInvalidBlockRoot*(
    dag: ChainDAGRef, initialSearchRoot: Eth2Digest,
    latestValidHash: Eth2Digest, defaultEarliestInvalidBlockRoot: Eth2Digest):
    Eth2Digest =
  # Earliest within a chain/fork in question, per LVH definition. Intended to
  # be called with `initialRoot` as the parent of the block regarding which a
  # newPayload or forkchoiceUpdated execution_status has been received as the
  # tests effectively require being able to access this before the BlockRef's
  # made. Therefore, to accommodate the EF consensus spec sync tests, and the
  # possibilities that the LVH might be an immediate parent or a more distant
  # ancestor special-case handling of an earliest invalid root as potentially
  # not being from this function's search, but being provided as a default by
  # the caller with access to the block.
  var curBlck = dag.getBlockRef(initialSearchRoot).valueOr:
    # Being asked to traverse a chain which the DAG doesn't know about -- but
    # that'd imply the block's otherwise invalid for CL as well as EL.
    return static(default(Eth2Digest))

  # Only allow this special case outside loop; it's when the LVH is the direct
  # parent of the reported invalid block
  if  curBlck.executionBlockRoot.isSome and
      curBlck.executionBlockRoot.get == latestValidHash:
    return defaultEarliestInvalidBlockRoot

  while true:
    # This was supposed to have been either caught by the pre-loop check or the
    # parent check.
    if  curBlck.executionBlockRoot.isSome and
        curBlck.executionBlockRoot.get == latestValidHash:
      doAssert false, "getEarliestInvalidBlockRoot: unexpected LVH in loop body"

    if (curBlck.parent.isNil) or
       curBlck.parent.executionBlockRoot.get(latestValidHash) ==
         latestValidHash:
      break
    curBlck = curBlck.parent

  curBlck.root
