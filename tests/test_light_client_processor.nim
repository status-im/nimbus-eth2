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
  let
    cfg = block:
      var res = defaultRuntimeConfig
      res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH + 1
      res

  const numValidators = SLOTS_PER_EPOCH
  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(
      cfg, makeTestDB(numValidators), validatorMonitor, {},
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
      doAssert added.isOk()
      dag.updateHead(added[], quarantine[])

  addBlocks(SLOTS_PER_EPOCH, 0.82)
  let
    genesis_validators_root = dag.genesis_validators_root
    trustedBlockRoot = dag.head.root
  proc getTrustedBlockRoot(): Option[Eth2Digest] =
    some trustedBlockRoot

  const
    lowPeriod = 0.SyncCommitteePeriod
    lastPeriodWithSupermajority = 3.SyncCommitteePeriod
    highPeriod = 5.SyncCommitteePeriod
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

      const storeDataFork = LightClientProcessor.storeDataFork
      let store = (ref Option[storeDataFork.LightClientStore])()
      var
        processor = LightClientProcessor.new(
          false, "", "", cfg, genesis_validators_root, finalizationMode,
          store, getBeaconTime, getTrustedBlockRoot, onStoreInitialized)
        res: Result[bool, VerifierError]

    test "Sync" & testNameSuffix:
      let bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check:
        bootstrap.kind > LightClientDataFork.None
        bootstrap.kind <= storeDataFork
      let upgradedBootstrap = bootstrap.migratingToDataFork(storeDataFork)
      template forkyBootstrap: untyped = upgradedBootstrap.forky(storeDataFork)
      setTimeToSlot(forkyBootstrap.header.beacon.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap)
      check:
        res.isOk
        numOnStoreInitializedCalls == 1
        store[].isSome

      # Reduce stack size by making this a `proc`
      proc applyPeriodWithSupermajority(period: SyncCommitteePeriod) =
        let update = dag.getLightClientUpdateForPeriod(period)
        check:
          update.kind > LightClientDataFork.None
          update.kind <= storeDataFork
        let upgradedUpdate = update.migratingToDataFork(storeDataFork)
        template forkyUpdate: untyped = upgradedUpdate.forky(storeDataFork)
        setTimeToSlot(forkyUpdate.signature_slot)
        res = processor[].storeObject(
          MsgSource.gossip, getBeaconTime(), update)
        check:
          res.isOk
          store[].isSome
          if forkyUpdate.finalized_header.beacon.slot >
              forkyBootstrap.header.beacon.slot:
            store[].get.finalized_header == forkyUpdate.finalized_header
          else:
            store[].get.finalized_header == forkyBootstrap.header
          store[].get.optimistic_header == forkyUpdate.attested_header

      for period in lowPeriod .. lastPeriodWithSupermajority:
        applyPeriodWithSupermajority(period)

      # Reduce stack size by making this a `proc`
      proc applyPeriodWithoutSupermajority(period: SyncCommitteePeriod) =
        let update = dag.getLightClientUpdateForPeriod(period)
        check:
          update.kind > LightClientDataFork.None
          update.kind <= storeDataFork
        let upgradedUpdate = update.migratingToDataFork(storeDataFork)
        template forkyUpdate: untyped = upgradedUpdate.forky(storeDataFork)
        setTimeToSlot(forkyUpdate.signature_slot)

        for i in 0 ..< 2:
          res = processor[].storeObject(
            MsgSource.gossip, getBeaconTime(), update)
          if finalizationMode == LightClientFinalizationMode.Optimistic or
              period == lastPeriodWithSupermajority + 1:
            if finalizationMode == LightClientFinalizationMode.Optimistic or
                i == 0:
              check:
                res.isOk
                store[].isSome
                store[].get.best_valid_update.isSome
                store[].get.best_valid_update.get.matches(forkyUpdate)
            else:
              check:
                res.isErr
                res.error == VerifierError.Duplicate
                store[].isSome
                store[].get.best_valid_update.isSome
                store[].get.best_valid_update.get.matches(forkyUpdate)
          else:
            check:
              res.isErr
              res.error == VerifierError.MissingParent
              store[].isSome
              store[].get.best_valid_update.isSome
              not store[].get.best_valid_update.get.matches(forkyUpdate)

          proc applyDuplicate() = # Reduce stack size by making this a `proc`
            res = processor[].storeObject(
              MsgSource.gossip, getBeaconTime(), update)
            if finalizationMode == LightClientFinalizationMode.Optimistic or
                period == lastPeriodWithSupermajority + 1:
              check:
                res.isErr
                res.error == VerifierError.Duplicate
                store[].isSome
                store[].get.best_valid_update.isSome
                store[].get.best_valid_update.get.matches(forkyUpdate)
            else:
              check:
                res.isErr
                res.error == VerifierError.MissingParent
                store[].isSome
                store[].get.best_valid_update.isSome
                not store[].get.best_valid_update.get.matches(forkyUpdate)

          applyDuplicate()
          time += chronos.minutes(15)
          for _ in 0 ..< 150:
            applyDuplicate()
            time += chronos.seconds(5)
          time += chronos.minutes(15)

          res = processor[].storeObject(
            MsgSource.gossip, getBeaconTime(), update)
          if finalizationMode == LightClientFinalizationMode.Optimistic:
            check:
              res.isErr
              res.error == VerifierError.Duplicate
              store[].isSome
              store[].get.best_valid_update.isNone
            if store[].get.finalized_header == forkyUpdate.attested_header:
              break
            check store[].get.finalized_header == forkyUpdate.finalized_header
          elif period == lastPeriodWithSupermajority + 1:
            check:
              res.isErr
              res.error == VerifierError.Duplicate
              store[].isSome
              store[].get.best_valid_update.isSome
              store[].get.best_valid_update.get.matches(forkyUpdate)
          else:
            check:
              res.isErr
              res.error == VerifierError.MissingParent
              store[].isSome
              store[].get.best_valid_update.isSome
              not store[].get.best_valid_update.get.matches(forkyUpdate)
        if finalizationMode == LightClientFinalizationMode.Optimistic:
          check store[].get.finalized_header == forkyUpdate.attested_header
        else:
          check store[].get.finalized_header != forkyUpdate.attested_header

      for period in lastPeriodWithSupermajority + 1 .. highPeriod:
        applyPeriodWithoutSupermajority(period)

      let
        previousFinalized = store[].get.finalized_header
        finalityUpdate = dag.getLightClientFinalityUpdate()
      check:
        finalityUpdate.kind > LightClientDataFork.None
        finalityUpdate.kind <= storeDataFork
      let upgradedFinalityUpdate =
        finalityUpdate.migratingToDataFork(storeDataFork)
      template forkyFinalityUpdate: untyped =
        upgradedFinalityUpdate.forky(storeDataFork)
      setTimeToSlot(forkyFinalityUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), finalityUpdate)
      if res.isOk:
        check:
          finalizationMode == LightClientFinalizationMode.Optimistic
          store[].isSome
          store[].get.finalized_header == previousFinalized
          store[].get.best_valid_update.isSome
          store[].get.best_valid_update.get.matches(forkyFinalityUpdate)
          store[].get.optimistic_header == forkyFinalityUpdate.attested_header
      elif finalizationMode == LightClientFinalizationMode.Optimistic:
        check res.error == VerifierError.Duplicate
      else:
        check res.error == VerifierError.MissingParent
      check numOnStoreInitializedCalls == 1

    test "Invalid bootstrap" & testNameSuffix:
      var bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check:
        bootstrap.kind > LightClientDataFork.None
        bootstrap.kind <= storeDataFork
      withForkyBootstrap(bootstrap):
        when lcDataFork > LightClientDataFork.None:
          forkyBootstrap.header.beacon.slot.inc()
      let upgradedBootstrap = bootstrap.migratingToDataFork(storeDataFork)
      template forkyBootstrap: untyped = upgradedBootstrap.forky(storeDataFork)
      setTimeToSlot(forkyBootstrap.header.beacon.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap)
      check:
        res.isErr
        res.error == VerifierError.Invalid
        numOnStoreInitializedCalls == 0

    test "Duplicate bootstrap" & testNameSuffix:
      let bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check:
        bootstrap.kind > LightClientDataFork.None
        bootstrap.kind <= storeDataFork
      let upgradedBootstrap = bootstrap.migratingToDataFork(storeDataFork)
      template forkyBootstrap: untyped = upgradedBootstrap.forky(storeDataFork)
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
      check:
        update.kind > LightClientDataFork.None
        update.kind <= storeDataFork
      let upgradedUpdate = update.migratingToDataFork(storeDataFork)
      template forkyUpdate: untyped = upgradedUpdate.forky(storeDataFork)
      setTimeToSlot(forkyUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), update)
      check:
        res.isErr
        res.error == VerifierError.MissingParent
        numOnStoreInitializedCalls == 0

    test "Missing bootstrap (finality update)" & testNameSuffix:
      let finalityUpdate = dag.getLightClientFinalityUpdate()
      check:
        finalityUpdate.kind > LightClientDataFork.None
        finalityUpdate.kind <= storeDataFork
      let upgradedFinalityUpdate =
        finalityUpdate.migratingToDataFork(storeDataFork)
      template forkyFinalityUpdate: untyped =
        upgradedFinalityUpdate.forky(storeDataFork)
      setTimeToSlot(forkyFinalityUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), finalityUpdate)
      check:
        res.isErr
        res.error == VerifierError.MissingParent
        numOnStoreInitializedCalls == 0

    test "Missing bootstrap (optimistic update)" & testNameSuffix:
      let optimisticUpdate = dag.getLightClientOptimisticUpdate()
      check:
        optimisticUpdate.kind > LightClientDataFork.None
        optimisticUpdate.kind <= storeDataFork
      let upgradedOptimisticUpdate =
        optimisticUpdate.migratingToDataFork(storeDataFork)
      template forkyOptimisticUpdate: untyped =
        upgradedOptimisticUpdate.forky(storeDataFork)
      setTimeToSlot(forkyOptimisticUpdate.signature_slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), optimisticUpdate)
      check:
        res.isErr
        res.error == VerifierError.MissingParent
        numOnStoreInitializedCalls == 0
