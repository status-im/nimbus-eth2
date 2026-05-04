# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Status libraries
  taskpools,
  # Beacon chain internals
  ../beacon_chain/consensus_object_pools/
    [block_clearance, block_quarantine, blockchain_dag],
  ../beacon_chain/spec/[forks, helpers, light_client_sync, state_transition],
  # Test utilities
  ./testutil, ./testdbutil

from ./testbcutil import addHeadBlock

suite "Light client" & preset():
  const  # Test config, should be long enough to cover interesting transitions
    headPeriod = 4.SyncCommitteePeriod
  let
    cfg = block:  # Fork schedule that covers each `LightClientDataFork`
      static: doAssert ConsensusFork.high == ConsensusFork.Heze
      var res = defaultRuntimeConfig
      res.ALTAIR_FORK_EPOCH = 0.SyncCommitteePeriod.start_epoch + 1
      res.BELLATRIX_FORK_EPOCH = 0.SyncCommitteePeriod.start_epoch + 2
      res.CAPELLA_FORK_EPOCH = 1.SyncCommitteePeriod.start_epoch + 0
      res.DENEB_FORK_EPOCH = 1.SyncCommitteePeriod.start_epoch + 1
      res.ELECTRA_FORK_EPOCH = 2.SyncCommitteePeriod.start_epoch + 0
      res.FULU_FORK_EPOCH = 2.SyncCommitteePeriod.start_epoch + 1
      res.GLOAS_FORK_EPOCH = 3.SyncCommitteePeriod.start_epoch + 0
      res.HEZE_FORK_EPOCH = 3.SyncCommitteePeriod.start_epoch + 1
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
      var slot = dag.headState.slot
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
      for blck in makeTestBlocks(
          dag.headState, cache, blocks.int, attested = attested,
          syncCommitteeRatio = syncCommitteeRatio, cfg = cfg):
        let added = withBlck(blck):
          const nilCallback = OnBlockAdded[consensusFork](nil)
          dag.addHeadBlock(verifier, forkyBlck, nilCallback)
        check: added.isOk()
        dag.updateHead(added[], quarantine, [])

  setup:
    const numValidators = SLOTS_PER_EPOCH
    let
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = ChainDAGRef.init(
        cfg, cfg.makeTestDB(numValidators), validatorMonitor, {},
        lcDataConfig = LightClientDataConfig(
          serve: true,
          importMode: LightClientDataImportMode.OnlyNew))
      quarantine = newClone(Quarantine.init(cfg))
      rng = HmacDrbgContext.new()
      taskpool = Taskpool.new()
    var
      verifier = BatchVerifier.init(rng, taskpool)

  test "Pre-Altair":
    # Genesis
    block:
      let
        update = dag.getLightClientUpdateForPeriod(0.SyncCommitteePeriod)
        finalityUpdate = dag.getLightClientFinalityUpdate
        optimisticUpdate = dag.getLightClientOptimisticUpdate
      check:
        dag.headState.kind == ConsensusFork.Phase0
        update.kind == LightClientDataFork.None
        finalityUpdate.kind == LightClientDataFork.None
        optimisticUpdate.kind == LightClientDataFork.None

    # Advance to last slot before Altair
    dag.advanceToSlot(altairStartSlot - 1, verifier, quarantine[])
    block:
      let
        update = dag.getLightClientUpdateForPeriod(0.SyncCommitteePeriod)
        finalityUpdate = dag.getLightClientFinalityUpdate
        optimisticUpdate = dag.getLightClientOptimisticUpdate
      check:
        dag.headState.kind == ConsensusFork.Phase0
        update.kind == LightClientDataFork.None
        finalityUpdate.kind == LightClientDataFork.None
        optimisticUpdate.kind == LightClientDataFork.None

    # Advance to Altair
    dag.advanceToSlot(altairStartSlot, verifier, quarantine[])
    block:
      let
        update = dag.getLightClientUpdateForPeriod(0.SyncCommitteePeriod)
        finalityUpdate = dag.getLightClientFinalityUpdate
        optimisticUpdate = dag.getLightClientOptimisticUpdate
      check:
        dag.headState.kind == ConsensusFork.Altair
        update.kind == LightClientDataFork.None
        finalityUpdate.kind == LightClientDataFork.None
        optimisticUpdate.kind == LightClientDataFork.None

  test "Light client sync":
    # Advance to Altair
    dag.advanceToSlot(altairStartSlot, verifier, quarantine[])

    # Track trusted checkpoint for light client
    let
      genesis_validators_root = dag.genesis_validators_root
      trusted_block_root = dag.head.root

    # Advance to target slot
    const
      periodEpoch = headPeriod.start_epoch
      headSlot = (periodEpoch + 2).start_slot + 5
    dag.advanceToSlot(headSlot, verifier, quarantine[])
    let currentSlot = dag.headState.slot

    # Initialize light client store
    var bootstrap = dag.getLightClientBootstrap(trusted_block_root)
    check bootstrap.kind > LightClientDataFork.None
    var store: ForkedLightClientStore
    withForkyBootstrap(bootstrap):
      when lcDataFork > LightClientDataFork.None:
        var storeRes = newClone(initialize_light_client_store(
          trusted_block_root, forkyBootstrap, cfg))
        check storeRes[].isOk
        store = newClone(ForkedLightClientStore.init(storeRes[].get))[]

    # Sync to latest sync committee period
    var numIterations = 0
    while true:
      let storePeriod = withForkyStore(store):
        when lcDataFork > LightClientDataFork.None:
          forkyStore.finalized_header.beacon.slot.sync_committee_period
        else:
          GENESIS_SLOT.SyncCommitteePeriod
      if storePeriod + 1 >= headPeriod:
        break
      let
        period = withForkyStore(store):
          when lcDataFork > LightClientDataFork.None:
            if forkyStore.is_next_sync_committee_known:
              storePeriod + 1
            else:
              storePeriod
          else:
            storePeriod
        update = dag.getLightClientUpdateForPeriod(period)
      check update.kind > LightClientDataFork.None
      if update.kind > store.kind:
        withForkyUpdate(update):
          when lcDataFork > LightClientDataFork.None:
            store.migrateToDataFork(lcDataFork, cfg)
      withForkyStore(store):
        when lcDataFork > LightClientDataFork.None:
          # Reduce stack size by making this a `proc`
          proc syncToPeriod() =
            bootstrap.migrateToDataFork(lcDataFork, cfg)
            template forkyBootstrap: untyped = bootstrap.forky(lcDataFork)
            let upgradedUpdate = update.migratingToDataFork(lcDataFork, cfg)
            template forkyUpdate: untyped = upgradedUpdate.forky(lcDataFork)
            let res = process_light_client_update(
              forkyStore, forkyUpdate, currentSlot, cfg,
              genesis_validators_root)
            check:
              forkyUpdate.finalized_header.beacon.slot.sync_committee_period ==
                period
              res.isOk
              if forkyUpdate.finalized_header.beacon.slot >
                  forkyBootstrap.header.beacon.slot:
                forkyStore.finalized_header == forkyUpdate.finalized_header
              else:
                forkyStore.finalized_header == forkyBootstrap.header
          syncToPeriod()
      inc numIterations
      if numIterations > 20: doAssert false # Avoid endless loop on test failure

    # Sync to latest update
    let finalityUpdate = dag.getLightClientFinalityUpdate
    check finalityUpdate.kind > LightClientDataFork.None
    if finalityUpdate.kind > store.kind:
      withForkyFinalityUpdate(finalityUpdate):
        when lcDataFork > LightClientDataFork.None:
          store.migrateToDataFork(lcDataFork, cfg)
    withForkyStore(store):
      when lcDataFork > LightClientDataFork.None:
        let upgradedUpdate = finalityUpdate.migratingToDataFork(lcDataFork, cfg)
        template forkyUpdate: untyped = upgradedUpdate.forky(lcDataFork)
        let res = process_light_client_update(
          forkyStore, forkyUpdate, currentSlot, cfg, genesis_validators_root)
        check:
          forkyUpdate.attested_header.beacon.slot == dag.head.parent.slot
          res.isOk
          forkyStore.finalized_header == forkyUpdate.finalized_header
          forkyStore.optimistic_header == forkyUpdate.attested_header

  test "Init from checkpoint":
    let genesisState = assignClone dag.headState

    for epoch in [
        cfg.ALTAIR_FORK_EPOCH, cfg.CAPELLA_FORK_EPOCH,
        cfg.ELECTRA_FORK_EPOCH, cfg.GLOAS_FORK_EPOCH]:
      let consensusFork = cfg.consensusForkAtEpoch(epoch)
      for importMode in [
          LightClientDataImportMode.OnlyNew,
          LightClientDataImportMode.Full]:
        let finalizedSlot = (epoch + 2).start_slot
        dag.advanceToSlot(finalizedSlot, verifier, quarantine[])

        let cpDb = BeaconChainDB.new("", cfg, inMemory = true)
        ChainDAGRef.preInit(cpDb, genesisState[])
        ChainDAGRef.preInit(cpDb, dag.headState)
        let cpDag = ChainDAGRef.init(
          cfg, cpDb, validatorMonitor, {},
          lcDataConfig = LightClientDataConfig(
            serve: true, importMode: importMode))

        for i in 1'u64 .. 10:
          let headSlot = (finalizedSlot.epoch + i).start_slot
          cpDag.advanceToSlot(headSlot, verifier, quarantine[])

        let finalityUpdate = cpDag.getLightClientFinalityUpdate
        check finalityUpdate.kind >= lcDataForkAtConsensusFork(consensusFork)
        withForkyFinalityUpdate(finalityUpdate):
          when lcDataFork > LightClientDataFork.None:
            check:
              is_valid_light_client_header(
                forkyFinalityUpdate.attested_header, cfg)
              is_valid_light_client_header(
                forkyFinalityUpdate.finalized_header, cfg)

        const lcDataFork = LightClientDataFork.high
        let
          upgraded = finalityUpdate.migratingToDataFork(lcDataFork, cfg)
          header = upgraded.forky(lcDataFork).finalized_header
        check is_valid_light_client_header(header, cfg)
        withForkyFinalityUpdate(finalityUpdate):
          when lcDataFork >= LightClientDataFork.Capella:
            check get_lc_execution_root(header, cfg) ==
              get_lc_execution_root(forkyFinalityUpdate.finalized_header, cfg)
          else:
            check get_lc_execution_root(header, cfg) == ZERO_HASH
