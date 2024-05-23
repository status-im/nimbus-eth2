# beacon_chain
# Copyright (c) 2019-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# `block_sim` is a block, attestation, and sync committee simulator, whose task
# is to run the beacon chain without considering the network or the wall clock.
#
# Functionally, it achieves the same as the distributed beacon chain by
# producing blocks and attestations as if they were created by separate
# nodes, just like a set of `beacon_node` instances would.

import
  confutils, chronicles, eth/db/kvstore_sqlite3,
  chronos/timer, taskpools,
  ../tests/testblockutil,
  ../beacon_chain/el/eth1_chain,
  ../beacon_chain/spec/[forks, state_transition],
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/validators/validator_pool,
  ../beacon_chain/gossip_processing/[batch_validation, gossip_validation],
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_clearance],
  ./simutils

from std/random import Rand, gauss, initRand, rand
from std/stats import RunningStat
from ../beacon_chain/consensus_object_pools/attestation_pool import
  AttestationPool, addAttestation, addForkChoice, getAttestationsForBlock,
  getElectraAttestationsForBlock, init, prune
from ../beacon_chain/consensus_object_pools/block_quarantine import
  Quarantine, init
from ../beacon_chain/consensus_object_pools/sync_committee_msg_pool import
  SyncCommitteeMsgPool, addContribution, addSyncCommitteeMessage, init,
  produceContribution, produceSyncAggregate, pruneData
from ../beacon_chain/spec/beaconstate import
  get_beacon_committee, get_beacon_proposer_index,
  get_committee_count_per_slot, get_committee_indices
from ../beacon_chain/spec/state_transition_block import process_block
from ../tests/testbcutil import addHeadBlock

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tSignBlock = "Sign block"
  tAttest = "Have committee attest to block"
  tSyncCommittees = "Produce sync committee actions"
  tReplay = "Replay all produced blocks"

# TODO The rest of nimbus-eth2 uses only the forked version of these, and in
# general it's better for the validator_duties caller to use the forkedstate
# version, so isolate these here pending refactoring of block_sim to prefer,
# when possible, to also use the forked version. It'll be worth keeping some
# example of the non-forked version because it enables fork bootstrapping.
proc makeSimulationBlock(
    cfg: RuntimeConfig,
    state: var deneb.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[phase0.Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: deneb.ExecutionPayloadForSigning,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackHashedProc[deneb.HashedBeaconState],
    cache: var StateCache,
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags = {}): Result[deneb.BeaconBlock, cstring] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  # To create a block, we'll first apply a partial block to the state, skipping
  # some validations.

  var blck = partialBeaconBlock(
    cfg, state, proposer_index, randao_reveal, eth1_data, graffiti,
    attestations, deposits, exits, sync_aggregate, execution_payload)

  let res = process_block(
    cfg, state.data, blck.asSigVerified(), verificationFlags, cache)

  if res.isErr:
    rollback(state)
    return err(res.error())

  state.root = hash_tree_root(state.data)
  blck.state_root = state.root

  ok(blck)

proc makeSimulationBlock(
    cfg: RuntimeConfig,
    state: var electra.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[electra.Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: electra.ExecutionPayloadForSigning,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackHashedProc[electra.HashedBeaconState],
    cache: var StateCache,
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags = {}): Result[electra.BeaconBlock, cstring] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  # To create a block, we'll first apply a partial block to the state, skipping
  # some validations.

  var blck = partialBeaconBlock(
    cfg, state, proposer_index, randao_reveal, eth1_data, graffiti,
    attestations, deposits, exits, sync_aggregate, execution_payload)

  let res = process_block(
    cfg, state.data, blck.asSigVerified(), verificationFlags, cache)

  if res.isErr:
    rollback(state)
    return err(res.error())

  state.root = hash_tree_root(state.data)
  blck.state_root = state.root

  ok(blck)

# TODO confutils is an impenetrable black box. how can a help text be added here?
cli do(slots = SLOTS_PER_EPOCH * 7,
       validators = SLOTS_PER_EPOCH * 500,
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.82,
       syncCommitteeRatio {.desc: "ratio of validators that perform sync committee actions in each round"} = 0.82,
       blockRatio {.desc: "ratio of slots with blocks"} = 1.0,
       replay = true):
  let
    (genesisState, depositTreeSnapshot) = loadGenesis(validators, false)
    genesisTime = float getStateField(genesisState[], genesis_time)
  const cfg = getSimulationConfig()

  echo "Starting simulation..."

  let db = BeaconChainDB.new("block_sim_db")
  defer: db.close()

  ChainDAGRef.preInit(db, genesisState[])
  db.putDepositContractSnapshot(depositTreeSnapshot)

  let rng = HmacDrbgContext.new()
  var
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})
    eth1Chain = Eth1Chain.init(cfg, db, 0, default Eth2Digest)
    merkleizer = DepositsMerkleizer.init(depositTreeSnapshot.depositContractState)
    taskpool =
      try:
        Taskpool.new()
      except Exception as exc:
        raiseAssert "Failed to initialize Taskpool: " & exc.msg
    verifier = BatchVerifier.init(rng, taskpool)
    quarantine = newClone(Quarantine.init())
    attPool = AttestationPool.init(dag, quarantine)
    batchCrypto = BatchCrypto.new(
      rng, eager = func(): bool = true,
      genesis_validators_root = dag.genesis_validators_root,
      taskpool).expect("working batcher")
    syncCommitteePool = newClone SyncCommitteeMsgPool.init(rng, cfg)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r = initRand(1)
    tmpState = assignClone(dag.headState)

  eth1Chain.addBlock Eth1Block(
    number: Eth1BlockNumber 1,
    timestamp: Eth1BlockTimestamp genesisTime)

  let replayState = assignClone(dag.headState)

  proc handleAttestations(slot: Slot) =
    let
      attestationHead = dag.head.atSlot(slot)

    dag.withUpdatedState(tmpState[], attestationHead.toBlockSlotId.expect("not nil")) do:
      let
        fork = getStateField(updatedState, fork)
        genesis_validators_root = getStateField(updatedState, genesis_validators_root)
        committees_per_slot =
          get_committee_count_per_slot(updatedState, slot.epoch, cache)

      for committee_index in get_committee_indices(committees_per_slot):
        let committee = get_beacon_committee(
          updatedState, slot, committee_index, cache)

        for index_in_committee, validator_index in committee:
          if rand(r, 1.0) <= attesterRatio:
            if tmpState.kind < ConsensusFork.Electra:
              let
                data = makeAttestationData(
                  updatedState, slot, committee_index, bid.root)
                sig =
                  get_attestation_signature(
                    fork, genesis_validators_root, data,
                    MockPrivKeys[validator_index])
                attestation = phase0.Attestation.init(
                  [uint64 index_in_committee], committee.len, data,
                  sig.toValidatorSig()).expect("valid data")

              attPool.addAttestation(
                attestation, [validator_index], sig, data.slot.start_beacon_time)
            else:
              var
                data = makeAttestationData(
                  updatedState, slot, committee_index, bid.root)
                committee_bits: BitArray[static(MAX_COMMITTEES_PER_SLOT.int)]
                aggregation_bits = ElectraCommitteeValidatorsBits.init(committee.len)
              let committeeidx = data.index
              aggregation_bits.setBit(index_in_committee)
              committee_bits.setBit(committeeidx)
              data.index = 0   # obviously, fix in makeAttestationData for Electra
              let
                sig =
                  get_attestation_signature(
                    fork, genesis_validators_root, data,
                    MockPrivKeys[validator_index])
                attestation = electra.Attestation(
                  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.1/specs/electra/validator.md#construct-attestation
                  aggregation_bits: aggregation_bits,
                  data: data,
                  committee_bits: committee_bits,
                  signature: sig.toValidatorSig())

              attPool.addAttestation(
                attestation, [validator_index], sig, data.slot.start_beacon_time)
    do:
      raiseAssert "withUpdatedState failed"

  proc handleSyncCommitteeActions(slot: Slot) =
    type
      Aggregator = object
        subcommitteeIdx: SyncSubcommitteeIndex
        validatorIdx: ValidatorIndex
        selectionProof: ValidatorSig

    let
      syncCommittee = @(dag.syncCommitteeParticipants(slot + 1))
      genesis_validators_root = dag.genesis_validators_root
      fork = dag.forkAtEpoch(slot.epoch)
      messagesTime = slot.attestation_deadline()
      contributionsTime = slot.sync_contribution_deadline()

    var aggregators: seq[Aggregator]

    for subcommitteeIdx in SyncSubcommitteeIndex:
      for validatorIdx in syncSubcommittee(syncCommittee, subcommitteeIdx):
        if rand(r, 1.0) > syncCommitteeRatio:
          continue

        let
          validatorPrivKey = MockPrivKeys[validatorIdx]
          signature = get_sync_committee_message_signature(
            fork, genesis_validators_root,
            slot, dag.head.root, validatorPrivKey)
          msg = SyncCommitteeMessage(
            slot: slot,
            beacon_block_root: dag.head.root,
            validator_index: uint64 validatorIdx,
            signature: signature.toValidatorSig)

        let res = waitFor noCancel dag.validateSyncCommitteeMessage(
          quarantine,
          batchCrypto,
          syncCommitteePool,
          msg,
          subcommitteeIdx,
          messagesTime,
          false)

        doAssert res.isOk

        let (bid, cookedSig, positions) = res.get()

        syncCommitteePool[].addSyncCommitteeMessage(
          msg.slot,
          bid,
          msg.validator_index,
          cookedSig,
          subcommitteeIdx,
          positions)

        let
          selectionProofSig = get_sync_committee_selection_proof(
            fork, genesis_validators_root, slot, subcommitteeIdx,
            validatorPrivKey).toValidatorSig

        if is_sync_committee_aggregator(selectionProofSig):
          aggregators.add Aggregator(
            subcommitteeIdx: subcommitteeIdx,
            validatorIdx: validatorIdx,
            selectionProof: selectionProofSig)

    for aggregator in aggregators:
      var contribution: SyncCommitteeContribution
      let contributionWasProduced = syncCommitteePool[].produceContribution(
        slot, dag.head.bid, aggregator.subcommitteeIdx, contribution)

      if contributionWasProduced:
        let
          contributionAndProof = ContributionAndProof(
            aggregator_index: uint64 aggregator.validatorIdx,
            contribution: contribution,
            selection_proof: aggregator.selectionProof)

          validatorPrivKey =
            MockPrivKeys[aggregator.validatorIdx.ValidatorIndex]

          signedContributionAndProof = SignedContributionAndProof(
            message: contributionAndProof,
            signature: get_contribution_and_proof_signature(
              fork, genesis_validators_root, contributionAndProof,
              validatorPrivKey).toValidatorSig)

          res = waitFor noCancel dag.validateContribution(
            quarantine,
            batchCrypto,
            syncCommitteePool,
            signedContributionAndProof,
            contributionsTime,
            false)
        if res.isOk():
          let (bid, sig, _) = res.get
          syncCommitteePool[].addContribution(
            signedContributionAndProof, bid, sig)
        else:
          # We ignore duplicates / already-covered contributions
          doAssert res.error()[0] == ValidationResult.Ignore

  proc getNewBlock[T](
      state: var ForkedHashedBeaconState, slot: Slot, cache: var StateCache): T =
    let
      finalizedEpochRef = dag.getFinalizedEpochRef()
      proposerIdx = get_beacon_proposer_index(
        state, cache, getStateField(state, slot)).get()
      privKey = MockPrivKeys[proposerIdx]
      eth1ProposalData = eth1Chain.getBlockProposalData(
        state,
        finalizedEpochRef.eth1_data,
        finalizedEpochRef.eth1_deposit_index)
      sync_aggregate =
        syncCommitteePool[].produceSyncAggregate(dag.head.bid, slot)
      hashedState =
        when T is deneb.SignedBeaconBlock:
          addr state.denebData
        elif T is electra.SignedBeaconBlock:
          addr state.electraData
        else:
          static: doAssert false
      message = makeSimulationBlock(
        cfg,
        hashedState[],
        proposerIdx,
        get_epoch_signature(
          getStateField(state, fork),
          getStateField(state, genesis_validators_root),
          slot.epoch, privKey).toValidatorSig(),
        eth1ProposalData.vote,
        default(GraffitiBytes),
        when T is electra.SignedBeaconBlock:
          attPool.getElectraAttestationsForBlock(state, cache)
        else:
          attPool.getAttestationsForBlock(state, cache),
        eth1ProposalData.deposits,
        BeaconBlockValidatorChanges(),
        sync_aggregate,
        (when T is electra.SignedBeaconBlock:
          default(electra.ExecutionPayloadForSigning)
        elif T is deneb.SignedBeaconBlock:
          default(deneb.ExecutionPayloadForSigning)
        else:
          static: doAssert false),
        static(default(SignedBLSToExecutionChangeList)),
        noRollback,
        cache)

    var newBlock = T(message: message.get())

    let blockRoot = withTimerRet(timers[tHashBlock]):
      hash_tree_root(newBlock.message)
    newBlock.root = blockRoot
    # Careful, state no longer valid after here because of the await..
    newBlock.signature = withTimerRet(timers[tSignBlock]):
      get_block_signature(
        getStateField(state, fork),
        getStateField(state, genesis_validators_root),
        newBlock.message.slot,
        blockRoot, privKey).toValidatorSig()

    newBlock

  # TODO when withUpdatedState's state template doesn't conflict with chronos's
  # HTTP server's state function, combine all proposeForkBlock functions into a
  # single generic function. Until https://github.com/nim-lang/Nim/issues/20811
  # is fixed, that generic function must take `blockRatio` as a parameter.
  proc proposeDenebBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withUpdatedState(tmpState[], dag.getBlockIdAtSlot(slot).expect("block")) do:
      let
        newBlock = getNewBlock[deneb.SignedBeaconBlock](updatedState, slot, cache)
        added = dag.addHeadBlock(verifier, newBlock) do (
            blckRef: BlockRef, signedBlock: deneb.TrustedSignedBeaconBlock,
            epochRef: EpochRef, unrealized: FinalityCheckpoints):
          # Callback add to fork choice if valid
          attPool.addForkChoice(
            epochRef, blckRef, unrealized, signedBlock.message,
            blckRef.slot.start_beacon_time)

      dag.updateHead(added[], quarantine[], [])
      if dag.needStateCachesAndForkChoicePruning():
        dag.pruneStateCachesDAG()
        attPool.prune()
    do:
      raiseAssert "withUpdatedState failed"

  proc proposeElectraBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withUpdatedState(tmpState[], dag.getBlockIdAtSlot(slot).expect("block")) do:
      let
        newBlock = getNewBlock[electra.SignedBeaconBlock](updatedState, slot, cache)
        added = dag.addHeadBlock(verifier, newBlock) do (
            blckRef: BlockRef, signedBlock: electra.TrustedSignedBeaconBlock,
            epochRef: EpochRef, unrealized: FinalityCheckpoints):
          # Callback add to fork choice if valid
          attPool.addForkChoice(
            epochRef, blckRef, unrealized, signedBlock.message,
            blckRef.slot.start_beacon_time)

      dag.updateHead(added[], quarantine[], [])
      if dag.needStateCachesAndForkChoicePruning():
        dag.pruneStateCachesDAG()
        attPool.prune()
    do:
      raiseAssert "withUpdatedState failed"

  var
    lastEth1BlockAt = genesisTime
    eth1BlockNum = 1000

  for i in 0..<slots:
    let
      slot = Slot(i + 1)
      t =
        if slot.is_epoch: tEpoch
        else: tBlock
      now = genesisTime + float(slot * SECONDS_PER_SLOT)

    while true:
      let nextBlockTime = lastEth1BlockAt +
                          max(1.0, gauss(r, float cfg.SECONDS_PER_ETH1_BLOCK, 3.0))
      if nextBlockTime > now:
        break

      inc eth1BlockNum
      var eth1Block = Eth1Block(
        hash: makeFakeHash(eth1BlockNum),
        number: Eth1BlockNumber eth1BlockNum,
        timestamp: Eth1BlockTimestamp nextBlockTime)

      let newDeposits = int clamp(gauss(r, 5.0, 8.0), 0.0, 1000.0)
      for i in 0 ..< newDeposits:
        let validatorIdx = merkleizer.getChunkCount.int
        let d = makeDeposit(validatorIdx, {skipBlsValidation})
        eth1Block.deposits.add d
        merkleizer.addChunk hash_tree_root(d).data

      eth1Block.depositRoot = merkleizer.getDepositsRoot
      eth1Block.depositCount = merkleizer.getChunkCount

      eth1Chain.addBlock eth1Block
      lastEth1BlockAt = nextBlockTime

    if blockRatio > 0.0:
      withTimer(timers[t]):
        case dag.cfg.consensusForkAtEpoch(slot.epoch)
        of ConsensusFork.Electra:   proposeElectraBlock(slot)
        of ConsensusFork.Deneb:     proposeDenebBlock(slot)
        of ConsensusFork.Phase0 .. ConsensusFork.Capella:
          doAssert false
    if attesterRatio > 0.0:
      withTimer(timers[tAttest]):
        handleAttestations(slot)
    if syncCommitteeRatio > 0.0:
      withTimer(timers[tSyncCommittees]):
        handleSyncCommitteeActions(slot)

    syncCommitteePool[].pruneData(slot)

    # TODO if attestation pool was smarter, it would include older attestations
    #      too!
    verifyConsensus(dag.headState, attesterRatio * blockRatio)

    if t == tEpoch:
      echo ". slot: ", shortLog(slot), " epoch: ", shortLog(slot.epoch)
    else:
      try:
        write(stdout, ".")
      except IOError:
        discard
      flushFile(stdout)

  if replay:
    withTimer(timers[tReplay]):
      var cache = StateCache()
      doAssert dag.updateState(
        replayState[], dag.getBlockIdAtSlot(Slot(slots)).expect("block"),
        false, cache)

  echo "Done!"

  printTimers(dag.headState, attesters, true, timers)