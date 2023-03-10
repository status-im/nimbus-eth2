# beacon_chain
# Copyright (c) 2019-2023 Status Research & Development GmbH
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
  confutils, chronicles, eth/db/kvstore_sqlite3,
  chronos/timer, eth/keys, taskpools,
  ../tests/testblockutil,
  ../beacon_chain/spec/[forks, state_transition],
  ../beacon_chain/spec/datatypes/[phase0, altair, bellatrix, deneb],
  ../beacon_chain/[beacon_chain_db, beacon_clock],
  ../beacon_chain/eth1/eth1_monitor,
  ../beacon_chain/validators/validator_pool,
  ../beacon_chain/gossip_processing/[batch_validation, gossip_validation],
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_quarantine,
                                          block_clearance, attestation_pool,
                                          sync_committee_msg_pool],
  ./simutils

from std/math import E, ln, sqrt
from std/random import Rand, initRand, rand
from std/stats import RunningStat
from std/strformat import `&`
from ../beacon_chain/spec/datatypes/capella import SignedBeaconBlock
from ../beacon_chain/spec/beaconstate import
  get_beacon_committee, get_beacon_proposer_index,
  get_committee_count_per_slot, get_committee_indices

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

from ../beacon_chain/spec/state_transition_block import process_block

# TODO The rest of nimbus-eth2 uses only the forked version of these, and in
# general it's better for the validator_duties caller to use the forkedstate
# version, so isolate these here pending refactoring of block_sim to prefer,
# when possible, to also use the forked version. It'll be worth keeping some
# example of the non-forked version because it enables fork bootstrapping.

proc makeSimulationBlock(
    cfg: RuntimeConfig,
    state: var phase0.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: bellatrix.ExecutionPayloadForSigning,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackHashedProc[phase0.HashedBeaconState],
    cache: var StateCache,
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags = {}): Result[phase0.BeaconBlock, cstring] =
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
    state: var altair.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: bellatrix.ExecutionPayloadForSigning,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackHashedProc[altair.HashedBeaconState],
    cache: var StateCache,
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags = {}): Result[altair.BeaconBlock, cstring] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  # To create a block, we'll first apply a partial block to the state, skipping
  # some validations.

  var blck = partialBeaconBlock(
    cfg, state, proposer_index, randao_reveal, eth1_data, graffiti,
    attestations, deposits, exits, sync_aggregate, execution_payload)

  # Signatures are verified elsewhere, so don't duplicate inefficiently here
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
    state: var bellatrix.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: bellatrix.ExecutionPayloadForSigning,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackHashedProc[bellatrix.HashedBeaconState],
    cache: var StateCache,
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags = {}): Result[bellatrix.BeaconBlock, cstring] =
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
    state: var capella.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: capella.ExecutionPayloadForSigning,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackHashedProc[capella.HashedBeaconState],
    cache: var StateCache,
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags = {}): Result[capella.BeaconBlock, cstring] =
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
    state: var deneb.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
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

# TODO confutils is an impenetrable black box. how can a help text be added here?
cli do(slots = SLOTS_PER_EPOCH * 6,
       validators = SLOTS_PER_EPOCH * 400, # One per shard is minimum
       attesterRatio {.desc: "ratio of validators that attest in each round"} = 0.82,
       syncCommitteeRatio {.desc: "ratio of validators that perform sync committee actions in each round"} = 0.82,
       blockRatio {.desc: "ratio of slots with blocks"} = 1.0,
       replay = true):
  let
    (genesisState, depositTreeSnapshot) = loadGenesis(validators, false)
    genesisTime = float getStateField(genesisState[], genesis_time)

  var
    cfg = defaultRuntimeConfig

  cfg.ALTAIR_FORK_EPOCH = 1.Epoch
  cfg.BELLATRIX_FORK_EPOCH = 2.Epoch
  cfg.CAPELLA_FORK_EPOCH = 3.Epoch
  cfg.DENEB_FORK_EPOCH = 4.Epoch

  echo "Starting simulation..."

  let db = BeaconChainDB.new("block_sim_db")
  defer: db.close()

  ChainDAGRef.preInit(db, genesisState[])
  db.putDepositTreeSnapshot(depositTreeSnapshot)

  var
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})
    eth1Chain = Eth1Chain.init(cfg, db, 0, default Eth2Digest)
    merkleizer = DepositsMerkleizer.init(depositTreeSnapshot.depositContractState)
    taskpool = Taskpool.new()
    verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)
    quarantine = newClone(Quarantine.init())
    attPool = AttestationPool.init(dag, quarantine)
    batchCrypto = BatchCrypto.new(
      keys.newRng(), eager = func(): bool = true,
      genesis_validators_root = dag.genesis_validators_root, taskpool)
    syncCommitteePool = newClone SyncCommitteeMsgPool.init(keys.newRng())
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
            let
              data = makeAttestationData(
                updatedState, slot, committee_index, bid.root)
              sig =
                get_attestation_signature(
                  fork, genesis_validators_root, data,
                  MockPrivKeys[validator_index])
              attestation = Attestation.init(
                [uint64 index_in_committee], committee.len, data,
                sig.toValidatorSig()).expect("valid data")

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
            fork, genesis_validators_root, slot, dag.head.root, validatorPrivKey)
          msg = SyncCommitteeMessage(
            slot: slot,
            beacon_block_root: dag.head.root,
            validator_index: uint64 validatorIdx,
            signature: signature.toValidatorSig)

        let res = waitFor dag.validateSyncCommitteeMessage(
          batchCrypto,
          syncCommitteePool,
          msg,
          subcommitteeIdx,
          messagesTime,
          false)

        doAssert res.isOk

        let (positions, cookedSig) = res.get()

        syncCommitteePool[].addSyncCommitteeMessage(
          msg.slot,
          msg.beacon_block_root,
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
        slot, dag.head.root, aggregator.subcommitteeIdx, contribution)

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

          res = waitFor dag.validateContribution(
            batchCrypto,
            syncCommitteePool,
            signedContributionAndProof,
            contributionsTime,
            false)
        if res.isOk():
          syncCommitteePool[].addContribution(
            signedContributionAndProof, res.get()[0])
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
        when T is phase0.SignedBeaconBlock:
          SyncAggregate.init()
        elif T is altair.SignedBeaconBlock or T is bellatrix.SignedBeaconBlock or
             T is capella.SignedBeaconBlock or T is deneb.SignedBeaconBlock:
          syncCommitteePool[].produceSyncAggregate(dag.head.root)
        else:
          static: doAssert false
      hashedState =
        when T is phase0.SignedBeaconBlock:
          addr state.phase0Data
        elif T is altair.SignedBeaconBlock:
          addr state.altairData
        elif T is bellatrix.SignedBeaconBlock:
          addr state.bellatrixData
        elif T is capella.SignedBeaconBlock:
          addr state.capellaData
        elif T is deneb.SignedBeaconBlock:
          addr state.denebData
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
        attPool.getAttestationsForBlock(state, cache),
        eth1ProposalData.deposits,
        BeaconBlockValidatorChanges(),
        sync_aggregate,
        when T is deneb.SignedBeaconBlock:
          default(deneb.ExecutionPayloadForSigning)
        elif T is capella.SignedBeaconBlock:
          default(capella.ExecutionPayloadForSigning)
        else:
          default(bellatrix.ExecutionPayloadForSigning),
        static(default(SignedBLSToExecutionChangeList)),
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
        getStateField(state, fork),
        getStateField(state, genesis_validators_root),
        newBlock.message.slot,
        blockRoot, privKey).toValidatorSig()

    newBlock

  # TODO when withUpdatedState's state template doesn't conflict with chronos's
  # HTTP server's state function, combine all proposeForkBlock functions into a
  # single generic function. Until https://github.com/nim-lang/Nim/issues/20811
  # is fixed, that generic function must take `blockRatio` as a parameter.
  proc proposePhase0Block(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withUpdatedState(tmpState[], dag.getBlockIdAtSlot(slot).expect("block")) do:
      let
        newBlock = getNewBlock[phase0.SignedBeaconBlock](updatedState, slot, cache)
        added = dag.addHeadBlock(verifier, newBlock) do (
            blckRef: BlockRef, signedBlock: phase0.TrustedSignedBeaconBlock,
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

  proc proposeAltairBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withUpdatedState(tmpState[], dag.getBlockIdAtSlot(slot).expect("block")) do:
      let
        newBlock = getNewBlock[altair.SignedBeaconBlock](updatedState, slot, cache)
        added = dag.addHeadBlock(verifier, newBlock) do (
            blckRef: BlockRef, signedBlock: altair.TrustedSignedBeaconBlock,
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

  proc proposeBellatrixBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withUpdatedState(tmpState[], dag.getBlockIdAtSlot(slot).expect("block")) do:
      let
        newBlock = getNewBlock[bellatrix.SignedBeaconBlock](updatedState, slot, cache)
        added = dag.addHeadBlock(verifier, newBlock) do (
            blckRef: BlockRef, signedBlock: bellatrix.TrustedSignedBeaconBlock,
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

  proc proposeCapellaBlock(slot: Slot) =
    if rand(r, 1.0) > blockRatio:
      return

    dag.withUpdatedState(tmpState[], dag.getBlockIdAtSlot(slot).expect("block")) do:
      let
        newBlock = getNewBlock[capella.SignedBeaconBlock](updatedState, slot, cache)
        added = dag.addHeadBlock(verifier, newBlock) do (
            blckRef: BlockRef, signedBlock: capella.TrustedSignedBeaconBlock,
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
        of ConsensusFork.Deneb:     proposeDenebBlock(slot)
        of ConsensusFork.Capella:   proposeCapellaBlock(slot)
        of ConsensusFork.Bellatrix: proposeBellatrixBlock(slot)
        of ConsensusFork.Altair:    proposeAltairBlock(slot)
        of ConsensusFork.Phase0:    proposePhase0Block(slot)
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
      echo &". slot: {shortLog(slot)} ",
        &"epoch: {shortLog(slot.epoch)}"
    else:
      write(stdout, ".")
      flushFile(stdout)

  if replay:
    withTimer(timers[tReplay]):
      var cache = StateCache()
      doAssert dag.updateState(
        replayState[], dag.getBlockIdAtSlot(Slot(slots)).expect("block"),
        false, cache)

  echo "Done!"

  printTimers(dag.headState, attesters, true, timers)
