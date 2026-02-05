# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronos,
  std/sequtils,
  unittest2,
  taskpools,
  ../beacon_chain/conf,
  ../beacon_chain/spec/[beaconstate, forks, helpers, state_transition],
  ../beacon_chain/gossip_processing/block_processor,
  ../beacon_chain/consensus_object_pools/[
    attestation_pool, blockchain_dag, blob_quarantine, block_quarantine,
    block_clearance, consensus_manager, envelope_quarantine,
  ],
  ../beacon_chain/el/el_manager,
  ./[testblockutil, testdbutil, testutil]

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
    let
      rng = HmacDrbgContext.new()
      cfg = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
        res.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
        res.CAPELLA_FORK_EPOCH = Epoch(1)
        res.DENEB_FORK_EPOCH = Epoch(2)
        res.ELECTRA_FORK_EPOCH = Epoch(3)
        res.FULU_FORK_EPOCH = Epoch(4)
        res
      db = cfg.makeTestDB(SLOTS_PER_EPOCH)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(ChainDAGRef, cfg, db, validatorMonitor, {})
      taskpool = Taskpool.new()
      quarantine = newClone(Quarantine.init(cfg))
      blobQuarantine = newClone(BlobQuarantine())
      dataColumnQuarantine = newClone(ColumnQuarantine())
      gloasColumnQuarantine = newClone(GloasColumnQuarantine())
      envelopeQuarantine = newClone(EnvelopeQuarantine())
      attestationPool = newClone(AttestationPool.init(dag, quarantine))
      elManager = new ELManager # TODO: initialise this properly
      actionTracker = default(ActionTracker)
      consensusManager = ConsensusManager.new(
        dag,
        attestationPool,
        quarantine,
        elManager,
        actionTracker,
        newClone(DynamicFeeRecipientsStore.init()),
        "",
        Opt.some default(Eth1Address),
        defaultGasLimit,
      )
      state = newClone(dag.headState)
      getTimeFn = proc(): BeaconTime =
        state[].slot.start_beacon_time(cfg.timeParams)
      batchVerifier = BatchVerifier.new(rng, taskpool)
    var
      cache: StateCache
      info: ForkedEpochInfo

    cfg.process_slots(state[], cfg.lastPremergeSlotInTestCfg, cache, info, {}).expect(
      "OK"
    )

  asyncTest "Reverse order block add & get" & preset():
    let
      processor = BlockProcessor.new(
        false, "", "", batchVerifier, consensusManager, validatorMonitor,
        blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
        envelopeQuarantine, getTimeFn,
      )
      b1 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      b2 = addTestBlock(state[], cache, cfg = cfg).bellatrixData

      missing = await processor.addBlock(MsgSource.gossip, b2, noSidecars)

    check:
      missing.error == VerifierError.MissingParent
      not dag.containsForkBlock(b2.root) # Unresolved, shouldn't show up

      FetchRecord(root: b1.root) in quarantine[].checkMissing(32)

    let
      status = await processor.addBlock(MsgSource.gossip, b1, noSidecars)
      b1Get = dag.getBlockRef(b1.root)

    check:
      status.isOk
      b1Get.isSome()
      dag.containsForkBlock(b1.root)
      not dag.containsForkBlock(b2.root) # Async pipeline must still run

    while processor[].hasBlocks():
      poll()

    let b2Get = dag.getBlockRef(b2.root)

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
      validatorMonitor2 = newClone(ValidatorMonitor.init(cfg))
      dag2 = init(ChainDAGRef, cfg, db, validatorMonitor2, {})

    check:
      # ensure we loaded the correct head state
      dag2.head.root == b2.root
      dag2.headState.root == b2.message.state_root
      dag2.getBlockRef(b1.root).isSome()
      dag2.getBlockRef(b2.root).isSome()
      dag2.heads.len == 1
      dag2.heads[0].root == b2.root

  asyncTest "Invalidate block root" & preset():
    let
      b1 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      b2 = addTestBlock(state[], cache, cfg = cfg).bellatrixData
      processor = BlockProcessor.new(
        false, "", "", batchVerifier, consensusManager,
        validatorMonitor, blobQuarantine, dataColumnQuarantine,
        gloasColumnQuarantine, envelopeQuarantine, getTimeFn,
        invalidBlockRoots = @[b2.root])

    block:
      let res = await processor.addBlock(MsgSource.gossip, b2, noSidecars)
      check:
        res.isErr
        not dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)

    block:
      let res = await processor.addBlock(MsgSource.gossip, b1, noSidecars)
      check:
        res.isOk
        dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)
      while processor[].hasBlocks():
        poll()
      check:
        dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)

    block:
      let res = await processor.addBlock(MsgSource.gossip, b2, noSidecars)
      check:
        res == Result[void, VerifierError].err VerifierError.Invalid
        dag.containsForkBlock(b1.root)
        not dag.containsForkBlock(b2.root)

  asyncTest "Process a block from each fork (without blobs)" & preset():
    let processor = BlockProcessor.new(
      false, "", "", batchVerifier, consensusManager, validatorMonitor,
      blobQuarantine, dataColumnQuarantine, gloasColumnQuarantine,
      envelopeQuarantine, getTimeFn,
    )

    debugGloasComment "TODO testing"
    for consensusFork in ConsensusFork.Bellatrix .. ConsensusFork.Fulu:
      process_slots(
        cfg,
        state[],
        max(
          state[].slot + 1,
          cfg.consensusForkEpoch(consensusFork).start_slot,
        ),
        cache,
        info,
        {},
      )
      .expect("OK")

      withState(state[]):
        let b0 = addTestEngineBlock(cfg, consensusFork, forkyState, cache)
        discard await processor.addBlock(
          MsgSource.gossip, b0.blck, b0.blobsBundle.toSidecarsOpt(consensusFork)
        )
