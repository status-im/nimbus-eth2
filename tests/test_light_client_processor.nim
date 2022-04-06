# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
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
      serveLightClientData = true,
      importLightClientData = ImportLightClientData.OnlyNew)
    quarantine = newClone(Quarantine.init())
    taskpool = TaskPool.new()
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
      doAssert added.isOk()
      dag.updateHead(added[], quarantine[])

  addBlocks(SLOTS_PER_EPOCH, 0.75)
  let
    genesisValidatorsRoot = dag.genesisValidatorsRoot
    trustedBlockRoot = dag.head.root

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
        0.25
      else:
        0.75
    addBlocks(numFilledEpochsPerPeriod * SLOTS_PER_EPOCH, syncCommitteeRatio)

  for finalizationMode in LightClientFinalizationMode:
    let testNameSuffix = " (" & $finalizationMode & ")" & preset()

    setup:
      var time = chronos.seconds(0)
      proc getBeaconTime(): BeaconTime =
        BeaconTime(ns_since_genesis: time.nanoseconds)
      func setTimeToSlot(slot: Slot) =
        time = chronos.seconds((slot * SECONDS_PER_SLOT).int64)

      proc getTrustedBlockRoot(): Option[Eth2Digest] =
        some trustedBlockRoot

      var numDidInitializeStoreCalls = 0
      func didInitializeStore() = inc numDidInitializeStoreCalls

      let store = (ref Option[LightClientStore])()
      var
        processor = LightClientProcessor.new(
          false, "", "", cfg, genesisValidatorsRoot, finalizationMode,
          store, getBeaconTime, getTrustedBlockRoot, didInitializeStore)
        res: Result[void, BlockError]

    test "Standard sync" & testNameSuffix:
      let bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check bootstrap.isOk
      setTimeToSlot(bootstrap.get.header.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap.get)
      check:
        res.isOk
        numDidInitializeStoreCalls == 1

      for period in lowPeriod .. lastPeriodWithSupermajority:
        let update = dag.getBestLightClientUpdateForPeriod(period)
        check update.isSome
        setTimeToSlot(update.get.attested_header.slot + 1)
        res = processor[].storeObject(
          MsgSource.gossip, getBeaconTime(), update.get)
        check:
          res.isOk
          store[].isSome
          store[].get.finalized_header == update.get.finalized_header
          store[].get.optimistic_header == update.get.attested_header

    test "Forced update" & testNameSuffix:
      let bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check bootstrap.isOk
      setTimeToSlot(bootstrap.get.header.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap.get)
      check:
        res.isOk
        numDidInitializeStoreCalls == 1

      for period in lowPeriod .. lastPeriodWithSupermajority:
        let update = dag.getBestLightClientUpdateForPeriod(period)
        check update.isSome
        setTimeToSlot(update.get.attested_header.slot + 1)
        res = processor[].storeObject(
          MsgSource.gossip, getBeaconTime(), update.get)
        check:
          res.isOk
          store[].isSome
          store[].get.finalized_header == update.get.finalized_header
          store[].get.optimistic_header == update.get.attested_header

      for period in lastPeriodWithSupermajority + 1 .. highPeriod:
        let update = dag.getBestLightClientUpdateForPeriod(period)
        check update.isSome
        setTimeToSlot(update.get.attested_header.slot + 1)
        res = processor[].storeObject(
          MsgSource.gossip, getBeaconTime(), update.get)
        if finalizationMode == LightClientFinalizationMode.Optimistic or
            period == lastPeriodWithSupermajority + 1:
          check:
            res.isOk
            store[].isSome
            store[].get.best_valid_update.isSome
            store[].get.best_valid_update.get == update.get
        else:
          check:
            res.isErr
            res.error == BlockError.MissingParent
            store[].isSome
            store[].get.best_valid_update.isSome
            store[].get.best_valid_update.get != update.get

        res = processor[].storeObject(
          MsgSource.gossip, getBeaconTime(), update.get)
        if finalizationMode == LightClientFinalizationMode.Optimistic or
            period == lastPeriodWithSupermajority + 1:
          check:
            res.isErr
            res.error == BlockError.Duplicate
            store[].isSome
            store[].get.best_valid_update.isSome
            store[].get.best_valid_update.get == update.get
        else:
          check:
            res.isErr
            res.error == BlockError.MissingParent
            store[].isSome
            store[].get.best_valid_update.isSome
            store[].get.best_valid_update.get != update.get
        time += chronos.minutes(15)

        for _ in 0 ..< 150:
          time += chronos.seconds(5)
          res = processor[].storeObject(
            MsgSource.gossip, getBeaconTime(), update.get)
          if finalizationMode == LightClientFinalizationMode.Optimistic or
              period == lastPeriodWithSupermajority + 1:
            check:
              res.isErr
              res.error == BlockError.Duplicate
              store[].isSome
              store[].get.best_valid_update.isSome
              store[].get.best_valid_update.get == update.get
          else:
            check:
              res.isErr
              res.error == BlockError.MissingParent
              store[].isSome
              store[].get.best_valid_update.isSome
              store[].get.best_valid_update.get != update.get

        time += chronos.minutes(15)

        res = processor[].storeObject(
          MsgSource.gossip, getBeaconTime(), update.get)
        if finalizationMode == LightClientFinalizationMode.Optimistic:
          check:
            res.isErr
            res.error == BlockError.Duplicate
            store[].isSome
            store[].get.best_valid_update.isNone
            store[].get.finalized_header == update.get.finalized_header
        elif period == lastPeriodWithSupermajority + 1:
          check:
            res.isErr
            res.error == BlockError.Duplicate
            store[].isSome
            store[].get.best_valid_update.isSome
            store[].get.best_valid_update.get == update.get
        else:
          check:
            res.isErr
            res.error == BlockError.MissingParent
            store[].isSome
            store[].get.best_valid_update.isSome
            store[].get.best_valid_update.get != update.get

      let optimisticUpdate = dag.getOptimisticLightClientUpdate()
      check optimisticUpdate.isSome
      setTimeToSlot(optimisticUpdate.get.attested_header.slot + 1)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), optimisticUpdate.get)
      if res.isOk:
        check:
          finalizationMode == LightClientFinalizationMode.Optimistic
          store[].isSome
          store[].get.optimistic_header == optimisticUpdate.get.attested_header
      else:
        case finalizationMode
        of LightClientFinalizationMode.Strict:
          check res.error == BlockError.MissingParent
        of LightClientFinalizationMode.Optimistic:
          check res.error == BlockError.Duplicate
      check numDidInitializeStoreCalls == 1

    test "Invalid bootstrap" & testNameSuffix:
      var bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check bootstrap.isOk
      bootstrap.get.header.slot.inc()
      setTimeToSlot(bootstrap.get.header.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap.get)
      check:
        res.isErr
        res.error == BlockError.Invalid
        numDidInitializeStoreCalls == 0

    test "Duplicate bootstrap" & testNameSuffix:
      let bootstrap = dag.getLightClientBootstrap(trustedBlockRoot)
      check bootstrap.isOk
      setTimeToSlot(bootstrap.get.header.slot)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap.get)
      check:
        res.isOk
        numDidInitializeStoreCalls == 1
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), bootstrap.get)
      check:
        res.isErr
        res.error == BlockError.Duplicate
        numDidInitializeStoreCalls == 1

    test "Missing bootstrap (update)" & testNameSuffix:
      let update = dag.getBestLightClientUpdateForPeriod(lowPeriod)
      check update.isSome
      setTimeToSlot(update.get.attested_header.slot + 1)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), update.get)
      check:
        res.isErr
        res.error == BlockError.MissingParent
        numDidInitializeStoreCalls == 0

    test "Missing bootstrap (optimistic update)" & testNameSuffix:
      let optimisticUpdate = dag.getOptimisticLightClientUpdate()
      check optimisticUpdate.isSome
      setTimeToSlot(optimisticUpdate.get.attested_header.slot + 1)
      res = processor[].storeObject(
        MsgSource.gossip, getBeaconTime(), optimisticUpdate.get)
      check:
        res.isErr
        res.error == BlockError.MissingParent
        numDidInitializeStoreCalls == 0
