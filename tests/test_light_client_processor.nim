# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Status libraries
  chronos, eth/keys,
  # Beacon chain internals
  ../beacon_chain/consensus_object_pools/
    [block_clearance, block_quarantine, blockchain_dag],
  ../beacon_chain/gossip_processing/light_client_processor,
  ../beacon_chain/spec/[beacon_time, light_client_sync, state_transition],
  # Test utilities
  ./testutil, ./testdbutil

suite "Light client processor" & preset():
  const  # Test config, should be long enough to cover interesting transitions
    lowPeriod = 0.SyncCommitteePeriod
    lastPeriodWithSupermajority = 3.SyncCommitteePeriod
    highPeriod = 5.SyncCommitteePeriod
  let
    cfg = block:  # Fork schedule so that each `LightClientDataFork` is covered
      static: doAssert ConsensusFork.high == ConsensusFork.Deneb
      var res = defaultRuntimeConfig
      res.ALTAIR_FORK_EPOCH = 1.Epoch
      res.BELLATRIX_FORK_EPOCH = 2.Epoch
      res.CAPELLA_FORK_EPOCH = (EPOCHS_PER_SYNC_COMMITTEE_PERIOD * 1).Epoch
      res.DENEB_FORK_EPOCH = (EPOCHS_PER_SYNC_COMMITTEE_PERIOD * 2).Epoch
      res

  const numValidators = SLOTS_PER_EPOCH
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(
      cfg, makeTestDB(numValidators, cfg = cfg), validatorMonitor, {},
      lcDataConfig = LightClientDataConfig(
        serve: true,
        importMode: LightClientDataImportMode.OnlyNew))
    quarantine = newClone(Quarantine.init())
    taskpool = Taskpool.new()
  var verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)

  var cache: StateCache
  proc addBlocks(blocks: uint64, syncCommitteeRatio: float) =
    for blck in makeTestBlocks(dag.headState, cache, blocks.int,
                               attested = true, syncCommitteeRatio, cfg):
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
      doAssert added.isOk()
      dag.updateHead(added[], quarantine[], [])

  addBlocks(SLOTS_PER_EPOCH, 0.82)
  let
    genesis_validators_root = dag.genesis_validators_root
    trustedBlockRoot = dag.head.root
  proc getTrustedBlockRoot(): Option[Eth2Digest] =
    some trustedBlockRoot

  for period in lowPeriod .. highPeriod:
    const numFilledEpochsPerPeriod = 3
    let slot = ((period + 1).start_epoch - numFilledEpochsPerPeriod).start_slot
    var info: ForkedEpochInfo
    doAssert process_slots(cfg, dag.headState, slot,
                           cache, info, flags = {}).isOk()
    let syncCommitteeRatio =
      if period > lastPeriodWithSupermajority:
        0.62
      else:
        0.82
    addBlocks(numFilledEpochsPerPeriod * SLOTS_PER_EPOCH, syncCommitteeRatio)

  for finalizationMode in LightClientFinalizationMode:
    let testNameSuffix = " (" & $finalizationMode & ")" & preset()

    setup:
      var time = chronos.seconds(0)
      proc getBeaconTime(): BeaconTime =
        BeaconTime(ns_since_genesis: time.nanoseconds)
      func setTimeToSlot(slot: Slot) =
        time = chronos.seconds((slot * SECONDS_PER_SLOT).int64)

      var numOnStoreInitializedCalls = 0
      func onStoreInitialized() = inc numOnStoreInitializedCalls

      let store = (ref ForkedLightClientStore)()
      var
        processor = LightClientProcessor.new(
          false, "", "", cfg, genesis_validators_root, finalizationMode,
          store, getBeaconTime, getTrustedBlockRoot, onStoreInitialized)
        res: Result[bool, VerifierError]

    test "Sync" & testNameSuffix:
      var bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check bootstrap.kind > LightClientDataFork.None
      withForkyBootstrap(bootstrap):
        when lcDataFork > LightClientDataFork.None:
          setTimeToSlot(forkyBootstrap.header.beacon.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap)
      check:
        res.isOk
        numOnStoreInitializedCalls == 1
        store[].kind > LightClientDataFork.None

      # Reduce stack size by making this a `proc`
      proc applyPeriodWithSupermajority(period: SyncCommitteePeriod) =
        let update = dag.getLightClientUpdateForPeriod(period)
        check update.kind > LightClientDataFork.None
        withForkyUpdate(update):
          when lcDataFork > LightClientDataFork.None:
            setTimeToSlot(forkyUpdate.signature_slot)
        res = processor[].storeObject(
          MsgSource.gossip, getBeaconTime(), update)
        check update.kind <= store[].kind
        withForkyStore(store[]):
          when lcDataFork > LightClientDataFork.None:
            bootstrap.migrateToDataFork(lcDataFork)
            template forkyBootstrap: untyped = bootstrap.forky(lcDataFork)
            let upgraded = update.migratingToDataFork(lcDataFork)
            template forkyUpdate: untyped = upgraded.forky(lcDataFork)
            check:
              res.isOk
              if forkyUpdate.finalized_header.beacon.slot >
                  forkyBootstrap.header.beacon.slot:
                forkyStore.finalized_header == forkyUpdate.finalized_header
              else:
                forkyStore.finalized_header == forkyBootstrap.header
              forkyStore.optimistic_header == forkyUpdate.attested_header

      for period in lowPeriod .. lastPeriodWithSupermajority:
        applyPeriodWithSupermajority(period)

      # Reduce stack size by making this a `proc`
      proc applyPeriodWithoutSupermajority(
          period: SyncCommitteePeriod, update: ref ForkedLightClientUpdate) =
        for i in 0 ..< 2:
          res = processor[].storeObject(
            MsgSource.gossip, getBeaconTime(), update[])
          check update[].kind <= store[].kind
          if finalizationMode == LightClientFinalizationMode.Optimistic or
              period == lastPeriodWithSupermajority + 1:
            if finalizationMode == LightClientFinalizationMode.Optimistic or
                i == 0:
              withForkyStore(store[]):
                when lcDataFork > LightClientDataFork.None:
                  let upgraded = newClone(
                    update[].migratingToDataFork(lcDataFork))
                  template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                  check:
                    res.isOk
                    forkyStore.best_valid_update.isSome
                    forkyStore.best_valid_update.get.matches(forkyUpdate)
            else:
              withForkyStore(store[]):
                when lcDataFork > LightClientDataFork.None:
                  let upgraded = newClone(
                    update[].migratingToDataFork(lcDataFork))
                  template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                  check:
                    res.isErr
                    res.error == VerifierError.Duplicate
                    forkyStore.best_valid_update.isSome
                    forkyStore.best_valid_update.get.matches(forkyUpdate)
          else:
            withForkyStore(store[]):
              when lcDataFork > LightClientDataFork.None:
                let upgraded = newClone(
                  update[].migratingToDataFork(lcDataFork))
                template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                check:
                  res.isErr
                  res.error == VerifierError.MissingParent
                  forkyStore.best_valid_update.isSome
                  not forkyStore.best_valid_update.get.matches(forkyUpdate)

          # Reduce stack size by making this a `proc`
          proc applyDuplicate(update: ref ForkedLightClientUpdate) =
            res = processor[].storeObject(
              MsgSource.gossip, getBeaconTime(), update[])
            check update[].kind <= store[].kind
            if finalizationMode == LightClientFinalizationMode.Optimistic or
                period == lastPeriodWithSupermajority + 1:
              withForkyStore(store[]):
                when lcDataFork > LightClientDataFork.None:
                  let upgraded = newClone(
                    update[].migratingToDataFork(lcDataFork))
                  template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                  check:
                    res.isErr
                    res.error == VerifierError.Duplicate
                    forkyStore.best_valid_update.isSome
                    forkyStore.best_valid_update.get.matches(forkyUpdate)
            else:
              withForkyStore(store[]):
                when lcDataFork > LightClientDataFork.None:
                  let upgraded = newClone(
                    update[].migratingToDataFork(lcDataFork))
                  template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                  check:
                    res.isErr
                    res.error == VerifierError.MissingParent
                    forkyStore.best_valid_update.isSome
                    not forkyStore.best_valid_update.get.matches(forkyUpdate)

          applyDuplicate(update)
          time += chronos.minutes(15)
          for _ in 0 ..< 150:
            applyDuplicate(update)
            time += chronos.seconds(5)
          time += chronos.minutes(15)

          res = processor[].storeObject(
            MsgSource.gossip, getBeaconTime(), update[])
          check update[].kind <= store[].kind
          if finalizationMode == LightClientFinalizationMode.Optimistic:
            withForkyStore(store[]):
              when lcDataFork > LightClientDataFork.None:
                let upgraded = newClone(
                  update[].migratingToDataFork(lcDataFork))
                template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                check:
                  res.isErr
                  res.error == VerifierError.Duplicate
                  forkyStore.best_valid_update.isNone
                if forkyStore.finalized_header == forkyUpdate.attested_header:
                  break
                check forkyStore.finalized_header ==
                  forkyUpdate.finalized_header
          elif period == lastPeriodWithSupermajority + 1:
            withForkyStore(store[]):
              when lcDataFork > LightClientDataFork.None:
                let upgraded = newClone(
                  update[].migratingToDataFork(lcDataFork))
                template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                check:
                  res.isErr
                  res.error == VerifierError.Duplicate
                  forkyStore.best_valid_update.isSome
                  forkyStore.best_valid_update.get.matches(forkyUpdate)
          else:
            withForkyStore(store[]):
              when lcDataFork > LightClientDataFork.None:
                let upgraded = newClone(
                  update[].migratingToDataFork(lcDataFork))
                template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
                check:
                  res.isErr
                  res.error == VerifierError.MissingParent
                  forkyStore.best_valid_update.isSome
                  not forkyStore.best_valid_update.get.matches(forkyUpdate)

      for period in lastPeriodWithSupermajority + 1 .. highPeriod:
        let update = newClone(dag.getLightClientUpdateForPeriod(period))
        check update[].kind > LightClientDataFork.None
        withForkyUpdate(update[]):
          when lcDataFork > LightClientDataFork.None:
            setTimeToSlot(forkyUpdate.signature_slot)

        applyPeriodWithoutSupermajority(period, update)

        if finalizationMode == LightClientFinalizationMode.Optimistic:
          withForkyStore(store[]):
            when lcDataFork > LightClientDataFork.None:
              let upgraded = newClone(
                update[].migratingToDataFork(lcDataFork))
              template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
              check forkyStore.finalized_header == forkyUpdate.attested_header
        else:
          withForkyStore(store[]):
            when lcDataFork > LightClientDataFork.None:
              let upgraded = newClone(
                update[].migratingToDataFork(lcDataFork))
              template forkyUpdate: untyped = upgraded[].forky(lcDataFork)
              check forkyStore.finalized_header != forkyUpdate.attested_header

      var oldFinalized {.noinit.}: ForkedLightClientHeader
      withForkyStore(store[]):
        when lcDataFork > LightClientDataFork.None:
          oldFinalized = ForkedLightClientHeader(kind: lcDataFork)
          oldFinalized.forky(lcDataFork) = forkyStore.finalized_header
        else: raiseAssert "Unreachable"
      let finalityUpdate = dag.getLightClientFinalityUpdate()
      check finalityUpdate.kind > LightClientDataFork.None
      withForkyFinalityUpdate(finalityUpdate):
        when lcDataFork > LightClientDataFork.None:
          setTimeToSlot(forkyFinalityUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), finalityUpdate)
      check finalityUpdate.kind <= store[].kind
      if res.isOk:
        withForkyStore(store[]):
          when lcDataFork > LightClientDataFork.None:
            oldFinalized.migrateToDataFork(lcDataFork)
            template forkyOldFinalized: untyped = oldFinalized.forky(lcDataFork)
            let upgraded = finalityUpdate.migratingToDataFork(lcDataFork)
            template forkyUpdate: untyped = upgraded.forky(lcDataFork)
            check:
              finalizationMode == LightClientFinalizationMode.Optimistic
              forkyStore.finalized_header == forkyOldFinalized
              forkyStore.best_valid_update.isSome
              forkyStore.best_valid_update.get.matches(forkyUpdate)
              forkyStore.optimistic_header == forkyUpdate.attested_header
      elif finalizationMode == LightClientFinalizationMode.Optimistic:
        check res.error == VerifierError.Duplicate
      else:
        check res.error == VerifierError.MissingParent
      check numOnStoreInitializedCalls == 1

    test "Invalid bootstrap" & testNameSuffix:
      var bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check bootstrap.kind > LightClientDataFork.None
      withForkyBootstrap(bootstrap):
        when lcDataFork > LightClientDataFork.None:
          forkyBootstrap.header.beacon.slot.inc()
          setTimeToSlot(forkyBootstrap.header.beacon.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap)
      check:
        res.isErr
        res.error == VerifierError.Invalid
        numOnStoreInitializedCalls == 0

    test "Duplicate bootstrap" & testNameSuffix:
      let bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check bootstrap.kind > LightClientDataFork.None
      withForkyBootstrap(bootstrap):
        when lcDataFork > LightClientDataFork.None:
          setTimeToSlot(forkyBootstrap.header.beacon.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap)
      check:
        res.isOk
        numOnStoreInitializedCalls == 1
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap)
      check:
        res.isErr
        res.error == VerifierError.Duplicate
        numOnStoreInitializedCalls == 1

    test "Missing bootstrap (update)" & testNameSuffix:
      let update = dag.getLightClientUpdateForPeriod(lowPeriod)
      check update.kind > LightClientDataFork.None
      withForkyUpdate(update):
        when lcDataFork > LightClientDataFork.None:
          setTimeToSlot(forkyUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), update)
      check:
        res.isErr
        res.error == VerifierError.MissingParent
        numOnStoreInitializedCalls == 0

    test "Missing bootstrap (finality update)" & testNameSuffix:
      let finalityUpdate = dag.getLightClientFinalityUpdate()
      check finalityUpdate.kind > LightClientDataFork.None
      withForkyFinalityUpdate(finalityUpdate):
        when lcDataFork > LightClientDataFork.None:
          setTimeToSlot(forkyFinalityUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), finalityUpdate)
      check:
        res.isErr
        res.error == VerifierError.MissingParent
        numOnStoreInitializedCalls == 0

    test "Missing bootstrap (optimistic update)" & testNameSuffix:
      let optimisticUpdate = dag.getLightClientOptimisticUpdate()
      check optimisticUpdate.kind > LightClientDataFork.None
      withForkyOptimisticUpdate(optimisticUpdate):
        when lcDataFork > LightClientDataFork.None:
          setTimeToSlot(forkyOptimisticUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), optimisticUpdate)
      check:
        res.isErr
        res.error == VerifierError.MissingParent
        numOnStoreInitializedCalls == 0
