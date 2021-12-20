# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronicles, chronos,
  std/[options, sequtils],
  unittest2,
  eth/keys, taskpools,
  ../beacon_chain/beacon_clock,
  ../beacon_chain/spec/[beaconstate, forks, helpers, state_transition],
  ../beacon_chain/gossip_processing/[block_processor, consensus_manager],
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, blockchain_dag, block_quarantine, block_clearance],
  ./testutil, ./testdbutil, ./testblockutil

proc pruneAtFinalization(dag: ChainDAGRef) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()

suite "Block processor" & preset():
  setup:
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)
      quarantine = newClone(Quarantine.init())
      attestationPool = newClone(AttestationPool.init(dag, quarantine))
      consensusManager = ConsensusManager.new(dag, attestationPool, quarantine)
      state = newClone(dag.headState.data)
      cache = StateCache()
      b1 = addTestBlock(state[], cache).phase0Data
      b2 = addTestBlock(state[], cache).phase0Data
      getTimeFn = proc(): BeaconTime = b2.message.slot.toBeaconTime()
      processor = BlockProcessor.new(
        false, "", "", keys.newRng(), taskpool, consensusManager,
        validatorMonitor, getTimeFn)

  test "Reverse order block add & get" & preset():
    let missing = processor[].storeBlock(
      MsgSource.gossip, b2.message.slot.toBeaconTime(), b2)
    check: missing.error == BlockError.MissingParent

    check:
      dag.get(b2.root).isNone() # Unresolved, shouldn't show up

      FetchRecord(root: b1.root) in quarantine[].checkMissing()

    let
      status = processor[].storeBlock(
        MsgSource.gossip, b2.message.slot.toBeaconTime(), b1)
      b1Get = dag.get(b1.root)

    check:
      status.isOk
      b1Get.isSome()
      dag.get(b2.root).isNone() # Async pipeline must still run

    discard processor.runQueueProcessingLoop()
    while processor[].hasBlocks():
      poll()

    let
      b2Get = dag.get(b2.root)

    check:
      b2Get.isSome()

      b2Get.get().refs.parent == b1Get.get().refs

    dag.updateHead(b2Get.get().refs, quarantine[])
    dag.pruneAtFinalization()

    # The heads structure should have been updated to contain only the new
    # b2 head
    check:
      dag.heads.mapIt(it) == @[b2Get.get().refs]

    # check that init also reloads block graph
    var
      validatorMonitor2 = newClone(ValidatorMonitor.init())
      dag2 = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor2, {})

    check:
      # ensure we loaded the correct head state
      dag2.head.root == b2.root
      getStateRoot(dag2.headState.data) == b2.message.state_root
      dag2.get(b1.root).isSome()
      dag2.get(b2.root).isSome()
      dag2.heads.len == 1
      dag2.heads[0].root == b2.root
