# beacon_chain
# Copyright (c) 2019-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# `block_sim` is a block, attestation, and sync committee simulator, whose task
# is to run the beacon chain without considering the network or the wall clock.
#
# Functionally, it achieves the same as the distributed beacon chain by
# producing blocks and attestations as if they were created by separate
# nodes, just like a set of `beacon_node` instances would.

import
  confutils,
  chronicles,
  eth/db/kvstore_sqlite3,
  chronos,
  chronos/timer,
  taskpools,
  ../beacon_chain/spec/[forks, state_transition],
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/gossip_processing/[batch_validation, gossip_validation],
  ../beacon_chain/consensus_object_pools/[blockchain_dag, block_clearance],
  ./simutils

from std/random import initRand, rand
from std/stats import RunningStat
from ../beacon_chain/consensus_object_pools/attestation_pool import
  AttestationPool, addAttestation, addForkChoice, getAttestationsForBlock, init, prune
from ../beacon_chain/consensus_object_pools/block_quarantine import Quarantine, init
from ../beacon_chain/consensus_object_pools/sync_committee_msg_pool import
  SyncCommitteeMsgPool, addContribution, addSyncCommitteeMessage, init,
  produceContribution, produceSyncAggregate, pruneData
from ../beacon_chain/spec/beaconstate import
  get_beacon_committee, get_beacon_proposer_index, get_committee_count_per_slot,
  get_committee_indices, get_ptc
from ../beacon_chain/spec/state_transition_block import process_block
from ../tests/testbcutil import addHeadBlock
from ../tests/testblockutil import makeAttestationData, MockPrivKeys, `[]`

type Timers = enum
  tBlock = "Process non-epoch slot with block"
  tEpoch = "Process epoch slot with block"
  tHashBlock = "Tree-hash block"
  tSignBlock = "Sign block"
  tAttest = "Have committee attest to block"
  tSyncCommittees = "Produce sync committee actions"
  tReplay = "Replay all produced blocks"
  tPayloadAttestations = "Produce payload attestations"

# TODO confutils is an impenetrable black box. how can a help text be added here?
cli do(
  slots = SLOTS_PER_EPOCH * 7,
  validators = SLOTS_PER_EPOCH * 500,
  attesterRatio {.desc: "ratio of validators that attest in each round".} = 0.82,
  syncCommitteeRatio {.
    desc: "ratio of validators that perform sync committee actions in each round"
  .} = 0.82,
  payloadAttestationRatio {.
    desc: "ratio of PTC validators that produce payload attestations"
  .} = 0.82,
  blockRatio {.desc: "ratio of slots with blocks".} = 1.0,
  replay = true
):
  let genesisState = loadGenesis(validators, false)
  const
    cfg = getSimulationConfig()
    BUILDER_TOP_UP = 10_000_000_000.Gwei

  echo "Starting simulation..."

  let db = BeaconChainDB.new("block_sim_db", cfg)
  defer:
    db.close()

  proc eager(): bool =
    true

  ChainDAGRef.preInit(db, genesisState[])
  let rng = HmacDrbgContext.new()
  var
    validatorMonitor = newClone(ValidatorMonitor.init(cfg))
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})
    taskpool =
      try:
        Taskpool.new()
      except Exception as exc:
        raiseAssert "Failed to initialize Taskpool: " & exc.msg
    verifier = BatchVerifier.init(rng, taskpool)
    quarantine = newClone(Quarantine.init(cfg))
    attPool = AttestationPool.init(dag, quarantine)
    batchCrypto = BatchCrypto.new(
      rng, cfg.timeParams, eager,
      genesis_validators_root = dag.genesis_validators_root, taskpool).expect(
        "working batcher")
    syncCommitteePool = newClone SyncCommitteeMsgPool.init(rng, cfg)
    timers: array[Timers, RunningStat]
    attesters: RunningStat
    r = initRand(1)
    tmpState = assignClone(dag.headState)

  let replayState = assignClone(dag.headState)

  var pendingPayloadAttestations: seq[gloas.PayloadAttestationMessage]

  proc handleAttestations(slot: Slot) =
    let attestationHead = dag.head.atSlot(slot)

    dag.withUpdatedState(tmpState[], attestationHead.toBlockSlotId.expect("not nil")):
      let
        fork = updatedState.fork
        genesis_validators_root = dag.genesis_validators_root
        committees_per_slot =
          get_committee_count_per_slot(updatedState, slot.epoch, cache)

      for committee_index in get_committee_indices(committees_per_slot):
        let committee = get_beacon_committee(updatedState, slot, committee_index, cache)

        for index_in_committee, validator_index in committee:
          if rand(r, 1.0) <= attesterRatio:
            if tmpState.kind < ConsensusFork.Electra:
              let
                data =
                  makeAttestationData(updatedState, slot, committee_index, bid.root)
                sig = get_attestation_signature(
                  fork, genesis_validators_root, data, MockPrivKeys[validator_index]
                )
                attestation = phase0.Attestation
                  .init(
                    [uint64 index_in_committee],
                    committee.len,
                    data,
                    sig.toValidatorSig(),
                  )
                  .expect("valid data")

              attPool.addAttestation(
                attestation,
                [validator_index],
                attestation.aggregation_bits.len,
                -1,
                sig,
                data.slot.start_beacon_time(cfg.timeParams))
            else:
              var data =
                makeAttestationData(updatedState, slot, committee_index, bid.root)
              data.index = 0 # fix in makeAttestationData for Electra
              let
                sig = get_attestation_signature(
                  fork, genesis_validators_root, data, MockPrivKeys[validator_index]
                )
                attestation = SingleAttestation(
                  committee_index: committee_index.distinctBase,
                  attester_index: validator_index.uint64,
                  data: data,
                  signature: sig.toValidatorSig(),
                )

              attPool.addAttestation(
                attestation,
                [validator_index],
                committee.len,
                index_in_committee,
                sig,
                data.slot.start_beacon_time(cfg.timeParams))
    do:
      raiseAssert "withUpdatedState failed"

  proc handleSyncCommitteeActions(slot: Slot) =
    type Aggregator = object
      subcommitteeIdx: SyncSubcommitteeIndex
      validatorIdx: ValidatorIndex
      selectionProof: ValidatorSig

    let
      syncCommittee = @(dag.syncCommitteeParticipants(slot + 1))
      genesis_validators_root = dag.genesis_validators_root
      fork = dag.forkAtEpoch(slot.epoch)
      consensusFork = dag.cfg.consensusForkAtEpoch(slot.epoch)
      messagesTime = slot.attestation_deadline(cfg.timeParams, consensusFork)
      contributionsTime = slot.sync_contribution_deadline(cfg.timeParams, consensusFork)

    var aggregators: seq[Aggregator]

    for subcommitteeIdx in SyncSubcommitteeIndex:
      for validatorIdx in syncSubcommittee(syncCommittee, subcommitteeIdx):
        if rand(r, 1.0) > syncCommitteeRatio:
          continue

        let
          validatorPrivKey = MockPrivKeys[validatorIdx]
          signature = get_sync_committee_message_signature(
            fork, genesis_validators_root, slot, dag.head.root, validatorPrivKey
          )
          msg = SyncCommitteeMessage(
            slot: slot,
            beacon_block_root: dag.head.root,
            validator_index: uint64 validatorIdx,
            signature: signature.toValidatorSig,
          )

        let res = waitFor noCancel dag.validateSyncCommitteeMessage(
          quarantine, batchCrypto, syncCommitteePool, msg, subcommitteeIdx,
          messagesTime, false,
        )

        doAssert res.isOk

        let (bid, cookedSig, positions) = res.get()

        syncCommitteePool[].addSyncCommitteeMessage(
          msg.slot, bid, msg.validator_index, cookedSig, subcommitteeIdx, positions
        )

        let selectionProofSig = get_sync_committee_selection_proof(
          fork, genesis_validators_root, slot, subcommitteeIdx, validatorPrivKey
        ).toValidatorSig

        if is_sync_committee_aggregator(selectionProofSig):
          aggregators.add Aggregator(
            subcommitteeIdx: subcommitteeIdx,
            validatorIdx: validatorIdx,
            selectionProof: selectionProofSig,
          )

    for aggregator in aggregators:
      var contribution: SyncCommitteeContribution
      let contributionWasProduced = syncCommitteePool[].produceContribution(
        slot, dag.head.bid, aggregator.subcommitteeIdx, contribution
      )

      if contributionWasProduced:
        let
          contributionAndProof = ContributionAndProof(
            aggregator_index: uint64 aggregator.validatorIdx,
            contribution: contribution,
            selection_proof: aggregator.selectionProof,
          )

          validatorPrivKey = MockPrivKeys[aggregator.validatorIdx]

          signedContributionAndProof = SignedContributionAndProof(
            message: contributionAndProof,
            signature: get_contribution_and_proof_signature(
              fork, genesis_validators_root, contributionAndProof, validatorPrivKey
            ).toValidatorSig,
          )

          res = waitFor noCancel dag.validateContribution(
            quarantine, batchCrypto, syncCommitteePool, signedContributionAndProof,
            contributionsTime, false,
          )
        if res.isOk():
          let (bid, sig, _) = res.get
          syncCommitteePool[].addContribution(signedContributionAndProof, bid, sig)
        else:
          # We ignore duplicates / already-covered contributions
          doAssert res.error()[0] == ValidationResult.Ignore

  proc handlePayloadAttestations(slot: Slot) =
    if slot == GENESIS_SLOT:
      return

    let previousSlot = slot - 1

    dag.withUpdatedState(tmpState[],
        dag.head.atSlot(slot).toBlockSlotId.expect("not nil")):
      let
        fork = updatedState.fork
        genesis_validators_root = dag.genesis_validators_root

      # We make the assumption that payload was present and blobs available
      let data = gloas.PayloadAttestationData(
        beacon_block_root: dag.head.root,
        slot: previousSlot,
        payload_present: true,
        blob_data_available: true
      )

      withState(updatedState):
        when consensusFork >= ConsensusFork.Gloas:
          for validator_index in get_ptc(forkyState.data, previousSlot, cache):
            if rand(r, 1.0) <= payloadAttestationRatio:
              let
                privKey = MockPrivKeys[validator_index]
                sig = get_payload_attestation_message_signature(
                  fork, genesis_validators_root,
                  data, privKey
                )
                message = gloas.PayloadAttestationMessage(
                  validator_index: validator_index.uint64,
                  data: data,
                  signature: sig.toValidatorSig())
              pendingPayloadAttestations.add(message)
    do:
      raiseAssert "withUpdatedState failed for payload attestations"

  proc aggregatePayloadAttestations(): PayloadAttestation =
    if pendingPayloadAttestations.len == 0:
      return PayloadAttestation()

    let data = pendingPayloadAttestations[0].data
    var aggregation_bits: BitArray[int(PTC_SIZE)]

    # For simulation, just create an aggregate with all participants
    for msg in pendingPayloadAttestations:
      if msg.data == data:
        let ptc_index = msg.validator_index mod PTC_SIZE
        aggregation_bits[ptc_index] = true

    let res = PayloadAttestation(
      aggregation_bits: aggregation_bits,
      data: data,
      signature: pendingPayloadAttestations[0].signature
    )

    pendingPayloadAttestations.setLen(0)

    res

  # These need to be captured in outer scope due to Nim issue with nested generic procs
  # See: https://github.com/nim-lang/Nim/issues/20811
  let blockRatio = blockRatio

  proc proposeBlock(
      consensusFork: static ConsensusFork,
      state: var ForkyHashedBeaconState,
      cache: var StateCache,
  ) =
    if rand(r, 1.0) > blockRatio:
      return

    let
      slot = state.data.slot
      proposerIdx = get_beacon_proposer_index(state.data, cache, slot).get()
      privKey = MockPrivKeys[proposerIdx]
      randao_reveal = get_epoch_signature(
        state.data.fork, state.data.genesis_validators_root, slot.epoch, privKey
      )
      sync_aggregate = syncCommitteePool[].produceSyncAggregate(dag.head.bid, slot)

    let
      epb =
        when consensusFork >= ConsensusFork.Gloas:
          let
            bid =
              ExecutionPayloadBid(
                parent_block_hash: state.data.latest_block_hash,
                parent_block_root: hash_tree_root(state.data.latest_block_header),
                block_hash: default(Eth2Digest),
                prev_randao:
                  get_randao_mix(state.data, get_current_epoch(state.data)),
                fee_recipient: default(ExecutionAddress),
                gas_limit: 30000000'u64,
                builder_index: BUILDER_INDEX_SELF_BUILD,
                slot: slot,
                value: 0.Gwei,
                execution_payment: 0.Gwei,
                blob_kzg_commitments: default(KzgCommitments))
          SignedExecutionPayloadBid(
            message: bid, signature: ValidatorSig.infinity())
        else:
          default(SignedExecutionPayloadBid)

      payload_attestations =
        when consensusFork >= ConsensusFork.Gloas:
          if slot > GENESIS_SLOT:
            let pa = aggregatePayloadAttestations()
            if pa.data.slot != GENESIS_SLOT:
              @[pa]
            else: newSeq[PayloadAttestation]()
          else: newSeq[PayloadAttestation]()
        else:
          newSeq[PayloadAttestation]()

      message = makeBeaconBlock(
        cfg,
        consensusFork,
        state,
        cache,
        proposerIdx,
        randao_reveal.toValidatorSig(),
        default(Eth1Data),
        default(GraffitiBytes),
        attPool.getAttestationsForBlock(state, cache),
        default(seq[Deposit]),
        default(BeaconBlockValidatorChanges),
        sync_aggregate,
        default(consensusFork.ExecutionPayloadForSigning),
        {},
        default(ExecutionRequests),
        epb,
        payload_attestations
      ).expect("block")

    var newBlock = consensusFork.SignedBeaconBlock(message: message)
    let blockRoot = withTimerRet(timers[tHashBlock]):
      hash_tree_root(newBlock.message)
    newBlock.root = blockRoot
    # Careful, state no longer valid after here because of the await..
    newBlock.signature = withTimerRet(timers[tSignBlock]):
      get_block_signature(
        state.data.fork, state.data.genesis_validators_root, newBlock.message.slot,
        blockRoot, privKey,
      )
      .toValidatorSig()

    # TODO without the OnBlockAdded cast, Nim can't figure out the type (?)
    let onAdded: OnBlockAdded[consensusFork] = proc(
        blckRef: BlockRef,
        signedBlock: consensusFork.TrustedSignedBeaconBlock,
        state: consensusFork.BeaconState,
        epochRef: EpochRef,
        unrealized: FinalityCheckpoints,
    ) =
      # Callback add to fork choice if valid
      attPool.addForkChoice(
        epochRef, blckRef, unrealized, signedBlock.message,
        blckRef.slot.start_beacon_time(cfg.timeParams),
      )

    let added = dag.addHeadBlock(verifier, newBlock, onAdded)

    dag.updateHead(added[], quarantine[], [])
    if dag.needStateCachesAndForkChoicePruning():
      dag.pruneStateCachesDAG()
      attPool.prune()

  for i in 0 ..< slots:
    let
      slot = Slot(i + 1)
      t = if slot.is_epoch: tEpoch else: tBlock

    if blockRatio > 0.0:
      withTimer(timers[t]):
        let bsi = dag.getBlockIdAtSlot(slot).expect("block")
        var cache = StateCache()
        doAssert dag.updateState(tmpState[], bsi, false, cache, dag.updateFlags)
        withState(tmpState[]):
          when consensusFork >= ConsensusFork.Bellatrix:
            proposeBlock(consensusFork, forkyState, cache)
          else:
            raiseAssert "Unsupported fork " & $consensusFork

    if attesterRatio > 0.0:
      withTimer(timers[tAttest]):
        handleAttestations(slot)
    if syncCommitteeRatio > 0.0:
      withTimer(timers[tSyncCommittees]):
        handleSyncCommitteeActions(slot)
    if payloadAttestationRatio > 0.0:
      withTimer(timers[tPayloadAttestations]):
        handlePayloadAttestations(slot)

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
        replayState[],
        dag.getBlockIdAtSlot(Slot(slots)).expect("block"),
        false,
        cache,
        dag.updateFlags,
      )

  echo "Done!"

  printTimers(dag.headState, attesters, true, timers)
