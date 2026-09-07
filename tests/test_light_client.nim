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
  stew/bitops2, taskpools,
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
          importMode: LightClientDataImportMode.OnlyNew,
          importBackfill: true))
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
        let storeRes = newClone(initialize_light_client_store(
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

        let cpDb = BeaconChainDB.new(
          "", cfg, inMemory = true, lightClientDataImportBackfill = true)
        ChainDAGRef.preInit(cpDb, genesisState[])
        ChainDAGRef.preInit(cpDb, dag.headState)
        let cpDag = ChainDAGRef.init(
          cfg, cpDb, validatorMonitor, {},
          lcDataConfig = LightClientDataConfig(
            serve: true, importMode: importMode, importBackfill: true))

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

suite "Light client block data" & preset():
  func createDigest(seed: byte): Eth2Digest =
    var res: Eth2Digest
    for i in 0 ..< res.data.len:
      res.data[i] = seed + i.byte
    res

  proc createBlock(
      consensusFork: static ConsensusFork): consensusFork.SignedBeaconBlock =
    var blck: consensusFork.SignedBeaconBlock
    template body: untyped = blck.message.body
    template sync_aggregate: untyped = body.sync_aggregate
    blck.message.proposer_index = 1337
    blck.message.parent_root = createDigest(1)
    blck.message.state_root = createDigest(2)
    body.eth1_data.deposit_root = createDigest(3)
    for i in countup(0, sync_aggregate.sync_committee_bits.len - 1, step = 3):
      sync_aggregate.sync_committee_bits.setBit(i)
    for i in 0 .. sync_aggregate.sync_committee_signature.blob.high:
      sync_aggregate.sync_committee_signature.blob[i] = 4 + i.byte
    const consensusFork = typeof(blck).kind
    when consensusFork >= ConsensusFork.Gloas:
      body.signed_execution_payload_bid.message.parent_block_hash =
        createDigest(5)
    elif consensusFork >= ConsensusFork.Bellatrix:
      body.execution_payload.block_hash = createDigest(5)
      doAssert body.execution_payload.transactions.add(
        bellatrix.Transaction(@[6.byte]))
      when consensusFork >= ConsensusFork.Capella:
        doAssert body.execution_payload.withdrawals.add(
          Withdrawal(validator_index: 7))
    blck

  withAll(ConsensusFork):
    when consensusFork >= ConsensusFork.Altair:
      let blck = consensusFork.createBlock()
      template body: untyped = blck.message.body
      let bodyRoot = body.hash_tree_root()
      const blckLcDataFork = lcDataForkAtConsensusFork(consensusFork)
      withAll(LightClientDataFork):
        test $consensusFork & " -> " & $lcDataFork:
          when lcDataFork >= blckLcDataFork:
            let blockData = blck.toLightClientBlockData(lcDataFork)
            check:
              blockData.proposer_index == blck.message.proposer_index
              blockData.state_root == blck.message.state_root
              blockData.sync_committee_bits ==
                body.sync_aggregate.sync_committee_bits
              blockData.sync_committee_signature_root ==
                body.sync_aggregate.sync_committee_signature.hash_tree_root()
              is_valid_normalized_merkle_branch(
                hash_tree_root([
                  blockData.sync_committee_bits.hash_tree_root(),
                  blockData.sync_committee_signature_root]),
                blockData.sync_aggregate_branch,
                blckLcDataFork.sync_aggregate_gindex,
                bodyRoot)
              blck.asTrusted().toLightClientBlockData(lcDataFork) == blockData
          else:
            when compiles(blck.toLightClientBlockData(lcDataFork)):
              check lcDataFork.LightClientBlockData is
                blckLcDataFork.LightClientBlockData

        when lcDataFork > LightClientDataFork.None:
          test $consensusFork & " -> " & $lcDataFork & " (with bootstrap)":
            var
              currentSyncCommittee: SyncCommittee
              currentBranch: lcDataFork.CurrentSyncCommitteeBranch
            for i, x in currentBranch.mpairs():
              x = createDigest(i.byte + 67)

            when lcDataFork == blckLcDataFork:
              let blockData1 = blck.toLightClientBlockData(lcDataFork)

              var bootstrapData2: lcDataFork.LightClientBootstrapData
              let blockData2 = blck.toLightClientBlockData(
                lcDataFork, currentSyncCommittee, currentBranch, bootstrapData2)

              var bootstrapData3: lcDataFork.LightClientBootstrapData
              let blockData3 = blck.toLightClientBlockData(
                lcDataFork, currentBranch, bootstrapData3)

              check:
                blockData2 == blockData1
                blockData3 == blockData1
                bootstrapData2.current_sync_committee ==
                  List[SyncCommittee, 1].init(@[currentSyncCommittee])
                bootstrapData3.current_sync_committee.len == 0
                bootstrapData2.current_sync_committee_branch == currentBranch
                bootstrapData3.current_sync_committee_branch == currentBranch

              for bootstrapData in [bootstrapData2, bootstrapData3]:
                when lcDataFork >= LightClientDataFork.Gloas:
                  template bid: auto = body.signed_execution_payload_bid
                  check:
                    bootstrapData.execution_block_hash ==
                      bid.message.parent_block_hash
                    is_valid_merkle_branch(
                      bootstrapData.execution_block_hash,
                      bootstrapData.execution_branch,
                      log2trunc(EXECUTION_BLOCK_HASH_GINDEX_GLOAS),
                      get_subtree_index(EXECUTION_BLOCK_HASH_GINDEX_GLOAS),
                      bodyRoot)
                elif lcDataFork >= LightClientDataFork.Capella:
                  template payload: auto = body.execution_payload
                  check:
                    bootstrapData.execution == payload.toExecutionPayloadHeader
                    is_valid_merkle_branch(
                      hash_tree_root(bootstrapData.execution),
                      bootstrapData.execution_branch,
                      log2trunc(EXECUTION_PAYLOAD_GINDEX),
                      get_subtree_index(EXECUTION_PAYLOAD_GINDEX),
                      bodyRoot)
                else:
                  discard  # No execution data present

            else:
              var bootstrapData: lcDataFork.LightClientBootstrapData
              when compiles(blck.toLightClientBlockData(lcDataFork,
                  currentSyncCommittee, currentBranch, bootstrapData)):
                check false
              when compiles(blck.toLightClientBlockData(
                  lcDataFork, currentBranch, bootstrapData)):
                check false
