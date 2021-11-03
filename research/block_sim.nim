# beacon_chain
# Copyright (c) 2019-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# `block_sim` is a block and attestation simulator similar to `state_sim` whose
# task is to run the beacon chain without considering the network or the
# wall clock. Functionally, it achieves the same as the distributed beacon chain
# by producing blocks and attestations as if they were created by separate
# nodes, just like a set of `beacon_node` instances would.
#
# Similar to `state_sim`, but uses the block and attestation pools along with
# a database, as if a real node was running.

import
  math, stats, times, strformat,
  tables, options, random, tables, os,
  confutils, chronicles, eth/db/kvstore_sqlite3,
  chronos/timer, eth/keys, taskpools,
  ../tests/testblockutil,
  ../beacon_chain/spec/[
    beaconstate, forks, helpers, signatures, state_transition],
  ../beacon_chain/spec/datatypes/[phase0, altair, merge],
  ../beacon_chain/[beacon_chain_db, beacon_clock],
  ../beacon_chain/eth1/eth1_monitor,
  ../beacon_chain/validators/validator_pool,
  ../beacon_chain/gossip_processing/gossip_validation,
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_quarantine,
                                          block_clearance, attestation_pool,
                                          sync_committee_msg_pool],
  ./simutils

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tSignBlock = "Sign block"
  tAttest = "Have committee attest to block"
  tSyncCommittees = "Produce sync committee actions"
  tReplay = "Replay all produced blocks"

template seconds(x: uint64): timer.Duration =
  timer.seconds(int(x))

func gauss(r: var Rand; mu = 0.0; sigma = 1.0): float =
  # TODO This is present in Nim 1.4
  const K = sqrt(2 / E)
  var
    a = 0.0
    b = 0.0
  while true:
    a = rand(r, 1.0)
    b = (2.0 * rand(r, 1.0) - 1.0) * K
    if  b * b <= -4.0 * a * a * ln(a): break
  mu + sigma * (b / a)

# TODO confutils is an impenetrable black box. how can a help text be added here?
cli do(slots = SLOTS_PER_EPOCH * 6,
       validators = SLOTS_PER_EPOCH * 400, # One per shard is minimum
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.82,
       syncCommitteeRatio {.desc: "ratio of validators that perform sync committee actions in each round"} = 0.75,
       blockRatio {.desc: "ratio of slots with blocks"} = 1.0,
       replay = true):
  let
    (state, depositContractSnapshot) = loadGenesis(validators, false)
    genesisBlock = get_initial_beacon_block(state[].data)
    genesisTime = float state[].data.genesis_time

  var
    validatorKeyToIndex = initTable[ValidatorPubKey, int]()
    cfg = defaultRuntimeConfig

  cfg.ALTAIR_FORK_EPOCH = 96.Slot.epoch
  cfg.MERGE_FORK_EPOCH = 160.Slot.epoch

  echo "Starting simulation..."

  let db = BeaconChainDB.new("block_sim_db")
  defer: db.close()

  ChainDAGRef.preInit(db, state[].data, state[].data, genesisBlock)
  putInitialDepositContractSnapshot(db, depositContractSnapshot)

  for i in 0 ..< state.data.validators.len:
    validatorKeyToIndex[state.data.validators[i].pubkey] = i

  var
    dag = ChainDAGRef.init(cfg, db, {})
    eth1Chain = Eth1Chain.init(cfg, db)
    merkleizer = depositContractSnapshot.createMerkleizer
    taskpool = Taskpool.new()
    quarantine = QuarantineRef.init(keys.newRng(), taskpool)
    attPool = AttestationPool.init(dag, quarantine)
    syncCommitteePool = newClone SyncCommitteeMsgPool.init()
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r = initRand(1)
    tmpState = assignClone(dag.headState)

  eth1Chain.addBlock Eth1Block(
    number: Eth1BlockNumber 1,
    timestamp: Eth1BlockTimestamp genesisTime,
    voteData: Eth1Data(
      deposit_root: merkleizer.getDepositsRoot,
      deposit_count: merkleizer.getChunkCount))

  let replayState = assignClone(dag.headState)

  proc handleAttestations(slot: Slot) =
    let
      attestationHead = dag.head.atSlot(slot)

    dag.withState(tmpState[], attestationHead):
      let committees_per_slot =
        get_committee_count_per_slot(stateData.data, slot.epoch, cache)

      for committee_index in 0'u64..<committees_per_slot:
        let committee = get_beacon_committee(
          stateData.data, slot, committee_index.CommitteeIndex, cache)

        for index_in_committee, validatorIdx in committee:
          if rand(r, 1.0) <= attesterRatio:
            let
              data = makeAttestationData(
                stateData.data, slot, committee_index.CommitteeIndex, blck.root)
              sig =
                get_attestation_signature(getStateField(stateData.data, fork),
                  getStateField(stateData.data, genesis_validators_root),
                  data, MockPrivKeys[validatorIdx])
            var aggregation_bits = CommitteeValidatorsBits.init(committee.len)
            aggregation_bits.setBit index_in_committee

            attPool.addAttestation(
              Attestation(
                data: data,
                aggregation_bits: aggregation_bits,
                signature: sig.toValidatorSig()
              ), [validatorIdx], sig, data.slot)

  proc handleSyncCommitteeActions(slot: Slot) =
    type
      Aggregator = object
        subcommitteeIdx: SyncSubcommitteeIndex
        validatorIdx: int
        selectionProof: ValidatorSig

    let
      syncCommittee = @(dag.syncCommitteeParticipants(slot + 1))
      genesisValidatorsRoot = dag.genesisValidatorsRoot
      fork = dag.forkAtEpoch(slot.epoch)
      signingRoot = sync_committee_msg_signing_root(
        fork, slot.epoch, genesisValidatorsRoot, dag.head.root)
      messagesTime = slot.toBeaconTime(seconds(SECONDS_PER_SLOT div 3))
      contributionsTime = slot.toBeaconTime(seconds(2 * SECONDS_PER_SLOT div 3))

    var aggregators: seq[Aggregator]

    for subcommitteeIdx in allSyncSubcommittees():
      for valKey in syncSubcommittee(syncCommittee, subcommitteeIdx):
        if rand(r, 1.0) > syncCommitteeRatio:
          continue

        let
          validatorIdx = validatorKeyToIndex[valKey]
          validarorPrivKey = MockPrivKeys[validatorIdx.ValidatorIndex]
          signature = blsSign(validarorPrivKey, signingRoot.data)
          msg = SyncCommitteeMessage(
            slot: slot,
            beacon_block_root: dag.head.root,
            validator_index: uint64 validatorIdx,
            signature: signature.toValidatorSig)

        let res = dag.validateSyncCommitteeMessage(
          syncCommitteePool[],
          msg,
          subcommitteeIdx,
          messagesTime,
          false)

        doAssert res.isOk

        let (positions, cookedSig) = res.get()

        syncCommitteePool[].addSyncCommitteeMsg(
          msg.slot,
          msg.beacon_block_root,
          msg.validator_index,
          cookedSig,
          subcommitteeIdx,
          positions)

        let
          selectionProofSigningRoot =
            sync_committee_selection_proof_signing_root(
              fork, genesisValidatorsRoot, slot, uint64 subcommitteeIdx)
          selectionProofSig = blsSign(
            validarorPrivKey, selectionProofSigningRoot.data).toValidatorSig

        if is_sync_committee_aggregator(selectionProofSig):
          aggregators.add Aggregator(
            subcommitteeIdx: subcommitteeIdx,
            validatorIdx: validatorIdx,
            selectionProof: selectionProofSig)

    for aggregator in aggregators:
      var contribution: SyncCommitteeContribution
      let contributionWasProduced = syncCommitteePool[].produceContribution(
        slot, dag.head.root, aggregator.subcommitteeIdx, contribution)

      if contributionWasProduced:
        let
          contributionAndProof = ContributionAndProof(
            aggregator_index: uint64 aggregator.validatorIdx,
            contribution: contribution,
            selection_proof: aggregator.selectionProof)

          signingRoot = contribution_and_proof_signing_root(
            fork, genesisValidatorsRoot, contributionAndProof)

          validarorPrivKey =
            MockPrivKeys[aggregator.validatorIdx.ValidatorIndex]

          signedContributionAndProof = SignedContributionAndProof(
            message: contributionAndProof,
            signature: blsSign(validarorPrivKey, signingRoot.data).toValidatorSig)

          res = dag.validateSignedContributionAndProof(
            syncCommitteePool[],
            signedContributionAndProof,
            contributionsTime,
            false)

        doAssert res.isOk

        syncCommitteePool[].addSyncContribution(
          signedContributionAndProof, res.get)

  proc getNewBlock[T](
      stateData: var StateData, slot: Slot, cache: var StateCache): T =
    let
      finalizedEpochRef = dag.getFinalizedEpochRef()
      proposerIdx = get_beacon_proposer_index(
        stateData.data, cache, getStateField(stateData.data, slot)).get()
      privKey = MockPrivKeys[proposerIdx]
      eth1ProposalData = eth1Chain.getBlockProposalData(
        stateData.data,
        finalizedEpochRef.eth1_data,
        finalizedEpochRef.eth1_deposit_index)
      sync_aggregate =
        when T is phase0.SignedBeaconBlock:
          SyncAggregate.init()
        elif T is altair.SignedBeaconBlock or T is merge.SignedBeaconBlock:
          syncCommitteePool[].produceSyncAggregate(dag.head.root)
        else:
          static: doAssert false
      hashedState =
        when T is phase0.SignedBeaconBlock:
          addr stateData.data.phase0Data
        elif T is altair.SignedBeaconBlock:
          addr stateData.data.altairData
        elif T is merge.SignedBeaconBlock:
          addr stateData.data.mergeData
        else:
          static: doAssert false
      message = makeBeaconBlock(
        cfg,
        hashedState[],
        proposerIdx,
        dag.head.root,
        privKey.genRandaoReveal(
          getStateField(stateData.data, fork),
          getStateField(stateData.data, genesis_validators_root),
          slot).toValidatorSig(),
        eth1ProposalData.vote,
        default(GraffitiBytes),
        attPool.getAttestationsForBlock(stateData.data, cache),
        eth1ProposalData.deposits,
        BeaconBlockExits(),
        sync_aggregate,
        default(ExecutionPayload),
        noRollback,
        cache)

    var
      newBlock = T(
        message: message.get()
      )

    let blockRoot = withTimerRet(timers[tHashBlock]):
      hash_tree_root(newBlock.message)
    newBlock.root = blockRoot
    # Careful, state no longer valid after here because of the await..
    newBlock.signature = withTimerRet(timers[tSignBlock]):
      get_block_signature(
        getStateField(stateData.data, fork),
        getStateField(stateData.data, genesis_validators_root),
        newBlock.message.slot,
        blockRoot, privKey).toValidatorSig()

    newBlock

  proc proposePhase0Block(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withState(tmpState[], dag.head.atSlot(slot)):
      let
        newBlock = getNewBlock[phase0.SignedBeaconBlock](stateData, slot, cache)
        added = dag.addRawBlock(quarantine, newBlock) do (
            blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
            epochRef: EpochRef):
          # Callback add to fork choice if valid
          attPool.addForkChoice(
            epochRef, blckRef, signedBlock.message, blckRef.slot)

      blck() = added[]
      dag.updateHead(added[], quarantine)
      if dag.needStateCachesAndForkChoicePruning():
        dag.pruneStateCachesDAG()
        attPool.prune()

  proc proposeAltairBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withState(tmpState[], dag.head.atSlot(slot)):
      let
        newBlock = getNewBlock[altair.SignedBeaconBlock](stateData, slot, cache)
        added = dag.addRawBlock(quarantine, newBlock) do (
            blckRef: BlockRef, signedBlock: altair.TrustedSignedBeaconBlock,
            epochRef: EpochRef):
          # Callback add to fork choice if valid
          attPool.addForkChoice(
            epochRef, blckRef, signedBlock.message, blckRef.slot)

      blck() = added[]
      dag.updateHead(added[], quarantine)
      if dag.needStateCachesAndForkChoicePruning():
        dag.pruneStateCachesDAG()
        attPool.prune()

  proc proposeMergeBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withState(tmpState[], dag.head.atSlot(slot)):
      let
        newBlock = getNewBlock[merge.SignedBeaconBlock](stateData, slot, cache)
        added = dag.addRawBlock(quarantine, newBlock) do (
            blckRef: BlockRef, signedBlock: merge.TrustedSignedBeaconBlock,
            epochRef: EpochRef):
          # Callback add to fork choice if valid
          attPool.addForkChoice(
            epochRef, blckRef, signedBlock.message, blckRef.slot)

      blck() = added[]
      dag.updateHead(added[], quarantine)
      if dag.needStateCachesAndForkChoicePruning():
        dag.pruneStateCachesDAG()
        attPool.prune()

  var
    lastEth1BlockAt = genesisTime
    eth1BlockNum = 1000

  for i in 0..<slots:
    let
      slot = Slot(i + 1)
      t =
        if slot.isEpoch: tEpoch
        else: tBlock
      now = genesisTime + float(slot * SECONDS_PER_SLOT)

    while true:
      let nextBlockTime = lastEth1BlockAt +
                          max(1.0, gauss(r, float defaultRuntimeConfig.SECONDS_PER_ETH1_BLOCK, 3.0))
      if nextBlockTime > now:
        break

      inc eth1BlockNum
      var eth1Block = Eth1Block(
        number: Eth1BlockNumber eth1BlockNum,
        timestamp: Eth1BlockTimestamp nextBlockTime,
        voteData: Eth1Data(
          block_hash: makeFakeHash(eth1BlockNum)))

      let newDeposits = int clamp(gauss(r, 5.0, 8.0), 0.0, 1000.0)
      for i in 0 ..< newDeposits:
        let validatorIdx = merkleizer.getChunkCount.int
        let d = makeDeposit(validatorIdx, {skipBLSValidation})
        validatorKeyToIndex[d.pubkey] = validatorIdx
        eth1Block.deposits.add d
        merkleizer.addChunk hash_tree_root(d).data

      eth1Block.voteData.deposit_root = merkleizer.getDepositsRoot
      eth1Block.voteData.deposit_count = merkleizer.getChunkCount

      eth1Chain.addBlock eth1Block
      lastEth1BlockAt = nextBlockTime

    if blockRatio > 0.0:
      withTimer(timers[t]):
        case dag.cfg.stateForkAtEpoch(slot.epoch)
        of BeaconStateFork.Merge:  proposeMergeBlock(slot)
        of BeaconStateFork.Altair: proposeAltairBlock(slot)
        of BeaconStateFork.Phase0: proposePhase0Block(slot)
    if attesterRatio > 0.0:
      withTimer(timers[tAttest]):
        handleAttestations(slot)
    if syncCommitteeRatio > 0.0:
      withTimer(timers[tSyncCommittees]):
        handleSyncCommitteeActions(slot)

    syncCommitteePool[].pruneData(slot)

    # TODO if attestation pool was smarter, it would include older attestations
    #      too!
    verifyConsensus(dag.headState.data, attesterRatio * blockRatio)

    if t == tEpoch:
      echo &". slot: {shortLog(slot)} ",
        &"epoch: {shortLog(slot.compute_epoch_at_slot)}"
    else:
      write(stdout, ".")
      flushFile(stdout)

  if replay:
    withTimer(timers[tReplay]):
      var cache = StateCache()
      dag.updateStateData(
        replayState[], dag.head.atSlot(Slot(slots)), false, cache)

  echo "Done!"

  printTimers(dag.headState.data, attesters, true, timers)
