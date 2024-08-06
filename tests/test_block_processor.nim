# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  chronos,
  std/sequtils,
  unittest2,
  taskpools,
  ../beacon_chain/conf,
  ../beacon_chain/spec/[beaconstate, forks, helpers, state_transition],
  ../beacon_chain/spec/datatypes/deneb,
  ../beacon_chain/gossip_processing/block_processor,
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, blockchain_dag, blob_quarantine, block_quarantine,
    block_clearance, consensus_manager],
  ../beacon_chain/el/el_manager,
  ./testutil, ./testdbutil, ./testblockutil

from chronos/unittest2/asynctests import asyncTest
from ../beacon_chain/spec/eth2_apis/dynamic_fee_recipients import
  DynamicFeeRecipientsStore, init
from ../beacon_chain/validators/action_tracker import ActionTracker
from ../beacon_chain/validators/keystore_management import KeymanagerHost

proc pruneAtFinalization(dag: ChainDAGRef) =
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()

suite "Block processor" & preset():
  setup:
    let rng = HmacDrbgContext.new()
    var
      db = makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(ChainDAGRef, defaultRuntimeConfig, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      quarantine = newClone(Quarantine.init())
      blobQuarantine = newClone(BlobQuarantine())
      attestationPool = newClone(AttestationPool.init(dag, quarantine))
      elManager = new ELManager # TODO: initialise this properly
      actionTracker: ActionTracker
      consensusManager = ConsensusManager.new(
        dag, attestationPool, quarantine, elManager, actionTracker,
        newClone(DynamicFeeRecipientsStore.init()), "",
        Opt.some default(Eth1Address), defaultGasLimit)
      state = newClone(dag.headState)
      cache = StateCache()
      b1 = addTestBlock(state[], cache).phase0Data
      b2 = addTestBlock(state[], cache).phase0Data
      getTimeFn = proc(): BeaconTime = b2.message.slot.start_beacon_time()
      processor = BlockProcessor.new(
        false, "", "", rng, taskpool, consensusManager,
        validatorMonitor, blobQuarantine, getTimeFn)
      processorFut = processor.runQueueProcessingLoop()

  asyncTest "Reverse order block add & get" & preset():
    let
      missing = await processor[].addBlock(
        MsgSource.gossip, ForkedSignedBeaconBlock.init(b2),
        Opt.none(ForkedBlobSidecars))

    check: missing.error == VerifierError.MissingParent

    check:
      not dag.containsForkBlock(b2.root) # Unresolved, shouldn't show up

      FetchRecord(root: b1.root) in quarantine[].checkMissing(32)

    let
      status = await processor[].addBlock(
        MsgSource.gossip, ForkedSignedBeaconBlock.init(b1),
        Opt.none(ForkedBlobSidecars))
      b1Get = dag.getBlockRef(b1.root)

    check:
      status.isOk
      b1Get.isSome()
      dag.containsForkBlock(b1.root)
      not dag.containsForkBlock(b2.root) # Async pipeline must still run

    while processor[].hasBlocks():
      poll()

    let
      b2Get = dag.getBlockRef(b2.root)

    check:
      b2Get.isSome()

      b2Get.get().parent == b1Get.get()

    dag.updateHead(b2Get.get(), quarantine[], [])
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
