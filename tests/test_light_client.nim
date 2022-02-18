# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Status libraries
  chronicles, eth/keys, stew/objects, taskpools,
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
      syncCommitteeRatio = 0.75) =
    var cache: StateCache
    const maxAttestedSlotsPerPeriod = 3 * SLOTS_PER_EPOCH
    while true:
      var slot = getStateField(dag.headState.data, slot)
      doAssert targetSlot >= slot
      if targetSlot == slot: break

      # When there is a large jump, skip to the end of the current period,
      # create blocks for a few epochs to finalize it, then proceed
      let
        nextPeriod = slot.sync_committee_period + 1
        periodEpoch = nextPeriod.start_epoch
        periodSlot = periodEpoch.start_slot
        checkpointSlot = periodSlot - maxAttestedSlotsPerPeriod
      if targetSlot > checkpointSlot:
        var info: ForkedEpochInfo
        doAssert process_slots(cfg, dag.headState.data, checkpointSlot,
                               cache, info, flags = {}).isOk()
        slot = checkpointSlot

      # Create blocks for final few epochs
      let blocks = min(targetSlot - slot, maxAttestedSlotsPerPeriod)
      for blck in makeTestBlocks(dag.headState.data, cache, blocks.int,
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
        serveLightClientData = true,
        importLightClientData = ImportLightClientData.OnlyNew)
      quarantine = newClone(Quarantine.init())
      taskpool = TaskPool.new()
    var verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)

  test "Pre-Altair":
    # Genesis
    check:
      dag.headState.data.kind == BeaconStateFork.Phase0
      dag.getBestLightClientUpdateForPeriod(0.SyncCommitteePeriod).isNone
      dag.getLatestLightClientUpdate.isNone

    # Advance to last slot before Altair
    dag.advanceToSlot(altairStartSlot - 1, verifier, quarantine[])
    check:
      dag.headState.data.kind == BeaconStateFork.Phase0
      dag.getBestLightClientUpdateForPeriod(0.SyncCommitteePeriod).isNone
      dag.getLatestLightClientUpdate.isNone

    # Advance to Altair
    dag.advanceToSlot(altairStartSlot, verifier, quarantine[])
    check:
      dag.headState.data.kind == BeaconStateFork.Altair
      dag.getBestLightClientUpdateForPeriod(0.SyncCommitteePeriod).isNone
      dag.getLatestLightClientUpdate.isNone

  test "Light client sync":
    # Advance to Altair
    dag.advanceToSlot(altairStartSlot, verifier, quarantine[])

    # Track trusted checkpoint for light client
    let
      genesis_validators_root = dag.genesisValidatorsRoot
      trusted_block_root = dag.headState.blck.root

    # Advance to target slot
    const
      headPeriod = 2.SyncCommitteePeriod
      periodEpoch = headPeriod.start_epoch
      headSlot = (periodEpoch + 2).start_slot + 5
    dag.advanceToSlot(headSlot, verifier, quarantine[])
    let currentSlot = getStateField(dag.headState.data, slot)

    # Initialize light client store
    let bootstrap = dag.getLightClientBootstrap(trusted_block_root)
    check bootstrap.isSome
    var storeRes = initialize_light_client_store(
      trusted_block_root, bootstrap.get)
    check storeRes.isOk
    template store(): auto = storeRes.get

    # Sync to latest sync committee period
    var numIterations = 0
    while store.finalized_header.slot.sync_committee_period + 1 < headPeriod:
      let
        period =
          if store.next_sync_committee.isZeroMemory:
            store.finalized_header.slot.sync_committee_period
          else:
            store.finalized_header.slot.sync_committee_period + 1
        bestUpdate = dag.getBestLightClientUpdateForPeriod(period)
        res = process_light_client_update(
          store, bestUpdate.get, currentSlot, cfg, genesis_validators_root)
      check:
        bestUpdate.isSome
        bestUpdate.get.finalized_header.slot.sync_committee_period == period
        res.isOk
        store.finalized_header == bestUpdate.get.finalized_header
      inc numIterations
      if numIterations > 20: doAssert false # Avoid endless loop on test failure

    # Sync to latest update
    let
      latestUpdate = dag.getLatestLightClientUpdate
      res = process_light_client_update(
        store, latestUpdate.get, currentSlot, cfg, genesis_validators_root)
    check:
      latestUpdate.isSome
      latestUpdate.get.attested_header.slot == dag.headState.blck.parent.slot
      res.isOk
      store.finalized_header == latestUpdate.get.finalized_header
      store.optimistic_header == latestUpdate.get.attested_header
