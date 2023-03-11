# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Status libraries
  eth/keys, taskpools,
  # Beacon chain internals
  ../beacon_chain/consensus_object_pools/
    [block_clearance, block_quarantine, blockchain_dag],
  ../beacon_chain/spec/[forks, helpers, light_client_sync, state_transition],
  # Test utilities
  ./testutil, ./testdbutil

suite "Light client" & preset():
  const  # Test config, should be long enough to cover interesting transitions
    headPeriod = 3.SyncCommitteePeriod
  let
    cfg = block:  # Fork schedule so that each `LightClientDataFork` is covered
      static: doAssert ConsensusFork.high == ConsensusFork.Deneb
      var res = defaultRuntimeConfig
      res.ALTAIR_FORK_EPOCH = 1.Epoch
      res.BELLATRIX_FORK_EPOCH = 2.Epoch
      res.CAPELLA_FORK_EPOCH = (EPOCHS_PER_SYNC_COMMITTEE_PERIOD * 1).Epoch
      res.DENEB_FORK_EPOCH = (EPOCHS_PER_SYNC_COMMITTEE_PERIOD * 2).Epoch
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
          of ConsensusFork.Phase0:
            const nilCallback = OnPhase0BlockAdded(nil)
            dag.addHeadBlock(verifier, blck.phase0Data, nilCallback)
          of ConsensusFork.Altair:
            const nilCallback = OnAltairBlockAdded(nil)
            dag.addHeadBlock(verifier, blck.altairData, nilCallback)
          of ConsensusFork.Bellatrix:
            const nilCallback = OnBellatrixBlockAdded(nil)
            dag.addHeadBlock(verifier, blck.bellatrixData, nilCallback)
          of ConsensusFork.Capella:
            const nilCallback = OnCapellaBlockAdded(nil)
            dag.addHeadBlock(verifier, blck.capellaData, nilCallback)
          of ConsensusFork.Deneb:
            const nilCallback = OnDenebBlockAdded(nil)
            dag.addHeadBlock(verifier, blck.denebData, nilCallback)

        check: added.isOk()
        dag.updateHead(added[], quarantine, [])

  setup:
    const num_validators = SLOTS_PER_EPOCH
    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = ChainDAGRef.init(
        cfg, makeTestDB(num_validators, cfg = cfg), validatorMonitor, {},
        lcDataConfig = LightClientDataConfig(
          serve: true,
          importMode: LightClientDataImportMode.OnlyNew))
      quarantine = newClone(Quarantine.init())
      taskpool = Taskpool.new()
    var verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)

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
    let currentSlot = getStateField(dag.headState, slot)

    # Initialize light client store
    var bootstrap = dag.getLightClientBootstrap(trusted_block_root)
    check bootstrap.kind > LightClientDataFork.None
    var store {.noinit.}: ForkedLightClientStore
    withForkyBootstrap(bootstrap):
      when lcDataFork > LightClientDataFork.None:
        var storeRes = initialize_light_client_store(
          trusted_block_root, forkyBootstrap, cfg)
        check storeRes.isOk
        store = ForkedLightClientStore(kind: lcDataFork)
        store.forky(lcDataFork) = storeRes.get

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
            store.migrateToDataFork(lcDataFork)
      withForkyStore(store):
        when lcDataFork > LightClientDataFork.None:
          bootstrap.migrateToDataFork(lcDataFork)
          template forkyBootstrap: untyped = bootstrap.forky(lcDataFork)
          let upgradedUpdate = update.migratingToDataFork(lcDataFork)
          template forkyUpdate: untyped = upgradedUpdate.forky(lcDataFork)
          let res = process_light_client_update(
            forkyStore, forkyUpdate, currentSlot, cfg, genesis_validators_root)
          check:
            forkyUpdate.finalized_header.beacon.slot.sync_committee_period ==
              period
            res.isOk
            if forkyUpdate.finalized_header.beacon.slot >
                forkyBootstrap.header.beacon.slot:
              forkyStore.finalized_header == forkyUpdate.finalized_header
            else:
              forkyStore.finalized_header == forkyBootstrap.header
      inc numIterations
      if numIterations > 20: doAssert false # Avoid endless loop on test failure

    # Sync to latest update
    let finalityUpdate = dag.getLightClientFinalityUpdate
    check finalityUpdate.kind > LightClientDataFork.None
    if finalityUpdate.kind > store.kind:
      withForkyFinalityUpdate(finalityUpdate):
        when lcDataFork > LightClientDataFork.None:
          store.migrateToDataFork(lcDataFork)
    withForkyStore(store):
      when lcDataFork > LightClientDataFork.None:
        let upgradedUpdate = finalityUpdate.migratingToDataFork(lcDataFork)
        template forkyUpdate: untyped = upgradedUpdate.forky(lcDataFork)
        let res = process_light_client_update(
          forkyStore, forkyUpdate, currentSlot, cfg, genesis_validators_root)
        check:
          forkyUpdate.attested_header.beacon.slot == dag.head.parent.slot
          res.isOk
          forkyStore.finalized_header == forkyUpdate.finalized_header
          forkyStore.optimistic_header == forkyUpdate.attested_header

  test "Init from checkpoint":
    # Fetch genesis state
    let genesisState = assignClone dag.headState

    # Advance to target slot for checkpoint
    let finalizedSlot =
      ((altairStartSlot.sync_committee_period + 1).start_epoch + 2).start_slot
    dag.advanceToSlot(finalizedSlot, verifier, quarantine[])

    # Initialize new DAG from checkpoint
    let cpDb = BeaconChainDB.new("", cfg = cfg, inMemory = true)
    ChainDAGRef.preInit(cpDb, genesisState[])
    ChainDAGRef.preInit(cpDb, dag.headState) # dag.getForkedBlock(dag.head.bid).get)
    let cpDag = ChainDAGRef.init(
      cfg, cpDb, validatorMonitor, {},
      lcDataConfig = LightClientDataConfig(
        serve: true,
        importMode: LightClientDataImportMode.Full))

    # Advance by a couple epochs
    for i in 1'u64 .. 10:
      let headSlot = (finalizedSlot.epoch + i).start_slot
      cpDag.advanceToSlot(headSlot, verifier, quarantine[])

    check true
