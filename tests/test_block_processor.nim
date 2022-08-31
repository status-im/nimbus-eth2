# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  chronos,
  std/[options, sequtils],
  unittest2,
  eth/keys, taskpools,
  ../beacon_chain/beacon_clock,
  ../beacon_chain/spec/[beaconstate, forks, helpers, state_transition],
  ../beacon_chain/gossip_processing/block_processor,
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, blockchain_dag, block_quarantine, block_clearance,
    consensus_manager],
  ../beacon_chain/eth1/eth1_monitor,
  ./testutil, ./testdbutil, ./testblockutil

from ../beacon_chain/spec/eth2_apis/dynamic_fee_recipients import
  DynamicFeeRecipientsStore, init
from ../beacon_chain/validators/keystore_management import KeymanagerHost
from ../beacon_chain/validators/validator_pool import ValidatorPool

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
      eth1Monitor = new Eth1Monitor
      attachedValidators: ref ValidatorPool
      keymanagerHost: ref KeymanagerHost
      consensusManager = ConsensusManager.new(
        dag, attestationPool, quarantine, eth1Monitor, attachedValidators,
        newClone(DynamicFeeRecipientsStore.init()), keymanagerHost,
        default(Eth1Address))
      state = newClone(dag.headState)
      cache = StateCache()
      b1 = addTestBlock(state[], cache).phase0Data
      b2 = addTestBlock(state[], cache).phase0Data
      getTimeFn = proc(): BeaconTime = b2.message.slot.start_beacon_time()
      processor = BlockProcessor.new(
        false, "", "", keys.newRng(), taskpool, consensusManager,
        validatorMonitor, getTimeFn, safeSlotsToImportOptimistically = 128)

  test "Reverse order block add & get" & preset():
    let missing = processor[].storeBlock(
      MsgSource.gossip, b2.message.slot.start_beacon_time(), b2,
      payloadValid = true)
    check: missing.error == BlockError.MissingParent

    check:
      not dag.containsForkBlock(b2.root) # Unresolved, shouldn't show up

      FetchRecord(root: b1.root) in quarantine[].checkMissing()

    let
      status = processor[].storeBlock(
        MsgSource.gossip, b2.message.slot.start_beacon_time(), b1,
        payloadValid = true)
      b1Get = dag.getBlockRef(b1.root)

    check:
      status.isOk
      b1Get.isSome()
      dag.containsForkBlock(b1.root)
      not dag.containsForkBlock(b2.root) # Async pipeline must still run

    discard processor.runQueueProcessingLoop()
    while processor[].hasBlocks():
      poll()

    let
      b2Get = dag.getBlockRef(b2.root)

    check:
      b2Get.isSome()

      b2Get.get().parent == b1Get.get()

    dag.updateHead(b2Get.get(), quarantine[])
    dag.pruneAtFinalization()

    # The heads structure should have been updated to contain only the new
    # b2 head
    check:
      dag.heads.mapIt(it) == @[b2Get.get()]

    # check that init also reloads block graph
    var
      validatorMonitor2 = newClone(ValidatorMonitor.init())
      dag2 = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor2, {})

    check:
      # ensure we loaded the correct head state
      dag2.head.root == b2.root
      getStateRoot(dag2.headState) == b2.message.state_root
      dag2.getBlockRef(b1.root).isSome()
      dag2.getBlockRef(b2.root).isSome()
      dag2.heads.len == 1
      dag2.heads[0].root == b2.root
