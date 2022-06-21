# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  # Status libraries
  eth/keys, stew/objects, taskpools,
  # Beacon chain internals
  ../beacon_chain/consensus_object_pools/
    [block_clearance, block_quarantine, blockchain_dag],
  ../beacon_chain/spec/[forks, helpers, light_client_sync, state_transition],
  # Test utilities
  ./testutil, ./testdbutil

suite "Light client" & preset():
  let
    cfg = block:
      var res = defaultRuntimeConfig
      res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH + 1
      res
    altairStartSlot = cfg.ALTAIR_FORK_EPOCH.start_slot

  proc advanceToSlot(
      dag: ChainDAGRef,
      targetSlot: Slot,
      verifier: var BatchVerifier,
      quarantine: var Quarantine,
      attested = true,
      syncCommitteeRatio = 0.82) =
    var cache: StateCache
    const maxAttestedSlotsPerPeriod = 3 * SLOTS_PER_EPOCH
    while true:
      var slot = getStateField(dag.headState, slot)
      doAssert targetSlot >= slot
      if targetSlot == slot: break

      # When there is a large jump, skip to the end of the current period,
      # create blocks for a few epochs to finalize it, then proceed
      let
        nextPeriod = slot.sync_committee_period + 1
        periodEpoch = nextPeriod.start_epoch
        periodSlot = periodEpoch.start_slot
        checkpointSlot = periodSlot - maxAttestedSlotsPerPeriod
      if targetSlot > checkpointSlot and checkpointSlot > dag.head.slot:
        var info: ForkedEpochInfo
        doAssert process_slots(cfg, dag.headState, checkpointSlot,
                               cache, info, flags = {}).isOk()
        slot = checkpointSlot

      # Create blocks for final few epochs
      let blocks = min(targetSlot - slot, maxAttestedSlotsPerPeriod)
      for blck in makeTestBlocks(dag.headState, cache, blocks.int,
                                 attested, syncCommitteeRatio, cfg):
        let added =
          case blck.kind
          of BeaconBlockFork.Phase0:
            const nilCallback = OnPhase0BlockAdded(nil)
            dag.addHeadBlock(verifier, blck.phase0Data, nilCallback)
          of BeaconBlockFork.Altair:
            const nilCallback = OnAltairBlockAdded(nil)
            dag.addHeadBlock(verifier, blck.altairData, nilCallback)
          of BeaconBlockFork.Bellatrix:
            const nilCallback = OnBellatrixBlockAdded(nil)
            dag.addHeadBlock(verifier, blck.bellatrixData, nilCallback)
        check: added.isOk()
        dag.updateHead(added[], quarantine)

  setup:
    const num_validators = SLOTS_PER_EPOCH
    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = ChainDAGRef.init(
        cfg, makeTestDB(num_validators), validatorMonitor, {},
        lightClientDataServe = true,
        lightClientDataImportMode = LightClientDataImportMode.OnlyNew)
      quarantine = newClone(Quarantine.init())
      taskpool = Taskpool.new()
    var verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)

  test "Pre-Altair":
    # Genesis
    check:
      dag.headState.kind == BeaconStateFork.Phase0
      dag.getLightClientUpdateForPeriod(0.SyncCommitteePeriod).isNone
      dag.getLightClientFinalityUpdate.isNone
      dag.getLightClientOptimisticUpdate.isNone

    # Advance to last slot before Altair
    dag.advanceToSlot(altairStartSlot - 1, verifier, quarantine[])
    check:
      dag.headState.kind == BeaconStateFork.Phase0
      dag.getLightClientUpdateForPeriod(0.SyncCommitteePeriod).isNone
      dag.getLightClientFinalityUpdate.isNone
      dag.getLightClientOptimisticUpdate.isNone

    # Advance to Altair
    dag.advanceToSlot(altairStartSlot, verifier, quarantine[])
    check:
      dag.headState.kind == BeaconStateFork.Altair
      dag.getLightClientUpdateForPeriod(0.SyncCommitteePeriod).isNone
      dag.getLightClientFinalityUpdate.isNone
      dag.getLightClientOptimisticUpdate.isNone

  test "Light client sync":
    # Advance to Altair
    dag.advanceToSlot(altairStartSlot, verifier, quarantine[])

    # Track trusted checkpoint for light client
    let
      genesis_validators_root = dag.genesis_validators_root
      trusted_block_root = dag.head.root

    # Advance to target slot
    const
      headPeriod = 2.SyncCommitteePeriod
      periodEpoch = headPeriod.start_epoch
      headSlot = (periodEpoch + 2).start_slot + 5
    dag.advanceToSlot(headSlot, verifier, quarantine[])
    let currentSlot = getStateField(dag.headState, slot)

    # Initialize light client store
    let bootstrap = dag.getLightClientBootstrap(trusted_block_root)
    check bootstrap.isOk
    var storeRes = initialize_light_client_store(
      trusted_block_root, bootstrap.get)
    check storeRes.isOk
    template store(): auto = storeRes.get

    # Sync to latest sync committee period
    var numIterations = 0
    while store.finalized_header.slot.sync_committee_period + 1 < headPeriod:
      let
        period =
          if store.is_next_sync_committee_known:
            store.finalized_header.slot.sync_committee_period + 1
          else:
            store.finalized_header.slot.sync_committee_period
        update = dag.getLightClientUpdateForPeriod(period)
        res = process_light_client_update(
          store, update.get, currentSlot, cfg, genesis_validators_root)
      check:
        update.isSome
        update.get.finalized_header.slot.sync_committee_period == period
        res.isOk
        if update.get.finalized_header.slot > bootstrap.get.header.slot:
          store.finalized_header == update.get.finalized_header
        else:
          store.finalized_header == bootstrap.get.header
      inc numIterations
      if numIterations > 20: doAssert false # Avoid endless loop on test failure

    # Sync to latest update
    let
      finalityUpdate = dag.getLightClientFinalityUpdate
      res = process_light_client_update(
        store, finalityUpdate.get, currentSlot, cfg, genesis_validators_root)
    check:
      finalityUpdate.isSome
      finalityUpdate.get.attested_header.slot == dag.head.parent.slot
      res.isOk
      store.finalized_header == finalityUpdate.get.finalized_header
      store.optimistic_header == finalityUpdate.get.attested_header

  test "Init from checkpoint":
    # Fetch genesis state
    let genesisState = assignClone dag.headState

    # Advance to target slot for checkpoint
    let finalizedSlot =
      ((altairStartSlot.sync_committee_period + 1).start_epoch + 2).start_slot
    dag.advanceToSlot(finalizedSlot, verifier, quarantine[])

    # Initialize new DAG from checkpoint
    let cpDb = BeaconChainDB.new("", inMemory = true)
    ChainDAGRef.preInit(
      cpDb, genesisState[],
      dag.headState, dag.getForkedBlock(dag.head.bid).get)
    let cpDag = ChainDAGRef.init(
      cfg, cpDb, validatorMonitor, {},
      lightClientDataServe = true,
      lightClientDataImportMode = LightClientDataImportMode.Full)

    # Advance by a couple epochs
    for i in 1'u64 .. 10:
      let headSlot = (finalizedSlot.epoch + i).start_slot
      cpDag.advanceToSlot(headSlot, verifier, quarantine[])

    check true
