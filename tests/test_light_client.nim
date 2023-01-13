# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Status libraries
  eth/keys, stew/objects, taskpools,
  # Beacon chain internals
  ../beacon_chain/consensus_object_pools/
    [block_clearance, block_quarantine, blockchain_dag],
  ../beacon_chain/spec/[forks, helpers, light_client_sync, state_transition],
  # Test utilities
  ./testutil, ./testdbutil

proc runTest(storeDataFork: static LightClientDataFork) =
  suite "Light client - " & $storeDataFork & preset():
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
            of BeaconBlockFork.Capella:
              const nilCallback = OnCapellaBlockAdded(nil)
              dag.addHeadBlock(verifier, blck.capellaData, nilCallback)
            of BeaconBlockFork.EIP4844:
              const nilCallback = OnEIP4844BlockAdded(nil)
              dag.addHeadBlock(verifier, blck.eip4844Data, nilCallback)

          check: added.isOk()
          dag.updateHead(added[], quarantine)

    setup:
      const num_validators = SLOTS_PER_EPOCH
      let
        validatorMonitor = newClone(ValidatorMonitor.init())
        dag = ChainDAGRef.init(
          cfg, makeTestDB(num_validators), validatorMonitor, {},
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
          dag.headState.kind == BeaconStateFork.Phase0
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
          dag.headState.kind == BeaconStateFork.Phase0
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
          dag.headState.kind == BeaconStateFork.Altair
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
        headPeriod = 2.SyncCommitteePeriod
        periodEpoch = headPeriod.start_epoch
        headSlot = (periodEpoch + 2).start_slot + 5
      dag.advanceToSlot(headSlot, verifier, quarantine[])
      let currentSlot = getStateField(dag.headState, slot)

      # Initialize light client store
      let bootstrap = dag.getLightClientBootstrap(trusted_block_root)
      check:
        bootstrap.kind > LightClientDataFork.None
        bootstrap.kind <= storeDataFork
      let upgradedBootstrap = bootstrap.migratingToDataFork(storeDataFork)
      template forkyBootstrap: untyped = upgradedBootstrap.forky(storeDataFork)
      var storeRes = initialize_light_client_store(
        trusted_block_root, forkyBootstrap, cfg)
      check storeRes.isOk
      template store(): auto = storeRes.get

      # Sync to latest sync committee period
      var numIterations = 0
      template storePeriod: SyncCommitteePeriod =
        store.finalized_header.beacon.slot.sync_committee_period
      while storePeriod + 1 < headPeriod:
        let
          period =
            if store.is_next_sync_committee_known:
              storePeriod + 1
            else:
              storePeriod
          update = dag.getLightClientUpdateForPeriod(period)
        check:
          update.kind > LightClientDataFork.None
          update.kind <= storeDataFork
        let upgradedUpdate = update.migratingToDataFork(storeDataFork)
        template forkyUpdate: untyped = upgradedUpdate.forky(storeDataFork)
        let res = process_light_client_update(
          store, forkyUpdate, currentSlot, cfg, genesis_validators_root)
        check:
          forkyUpdate.finalized_header.beacon.slot.sync_committee_period ==
            period
          res.isOk
          if forkyUpdate.finalized_header.beacon.slot >
              forkyBootstrap.header.beacon.slot:
            store.finalized_header == forkyUpdate.finalized_header
          else:
            store.finalized_header == forkyBootstrap.header
        inc numIterations
        if numIterations > 20: doAssert false # Avoid endless loop on test failure

      # Sync to latest update
      let finalityUpdate = dag.getLightClientFinalityUpdate
      check:
        finalityUpdate.kind > LightClientDataFork.None
        finalityUpdate.kind <= storeDataFork
      let upgradedFinalityUpdate =
        finalityUpdate.migratingToDataFork(storeDataFork)
      template forkyFinalityUpdate: untyped =
        upgradedFinalityUpdate.forky(storeDataFork)
      let res = process_light_client_update(
        store, forkyFinalityUpdate, currentSlot, cfg, genesis_validators_root)
      check:
        forkyFinalityUpdate.attested_header.beacon.slot == dag.head.parent.slot
        res.isOk
        store.finalized_header == forkyFinalityUpdate.finalized_header
        store.optimistic_header == forkyFinalityUpdate.attested_header

    test "Init from checkpoint":
      # Fetch genesis state
      let genesisState = assignClone dag.headState

      # Advance to target slot for checkpoint
      let finalizedSlot =
        ((altairStartSlot.sync_committee_period + 1).start_epoch + 2).start_slot
      dag.advanceToSlot(finalizedSlot, verifier, quarantine[])

      # Initialize new DAG from checkpoint
      let cpDb = BeaconChainDB.new("", inMemory = true)
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

withAll(LightClientDataFork):
  when lcDataFork > LightClientDataFork.None:
    runTest(lcDataFork)
