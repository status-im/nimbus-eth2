# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/tests/formats/networking/gossip_validation.md

import
  chronicles, chronos, taskpools,
  yaml/tojson,
  ../../beacon_chain/spec/forks,
  ../../beacon_chain/beacon_chain_db,
  ../../beacon_chain/consensus_object_pools/[blockchain_dag, column_quarantine],
  ../../beacon_chain/gossip_processing/[batch_validation, gossip_validation],
  ../testutil,
  ./fixtures_utils, ./os_ops

from std/json import
  JsonNode, getBiggestInt, getBool, getStr, hasKey, items, len, `[]`
from std/sequtils import toSeq
from std/strutils import parseEnum, startsWith
from chronos/unittest2/asynctests import asyncTest
from libp2p/protocols/pubsub/errors import ValidationResult
from minilru import contains
from snappy import decode
from ../../beacon_chain/consensus_object_pools/attestation_pool import
  AttestationPool, init, addAttestation
from ../../beacon_chain/consensus_object_pools/block_clearance import
  checkHeadBlock
from ../../beacon_chain/consensus_object_pools/block_quarantine import
  Quarantine, UnviableKind, addOrphan, addUnviable, init
from ../../beacon_chain/consensus_object_pools/envelope_quarantine import
  EnvelopeQuarantine, addUnviable, init
from ../../beacon_chain/consensus_object_pools/execution_payload_pool import
  ExecutionPayloadBidPool, addBid, init
from ../../beacon_chain/consensus_object_pools/inclusion_list_pool import
  InclusionListPool, addInclusionList, init
from ../../beacon_chain/consensus_object_pools/payload_attestation_pool import
  PayloadAttestationPool, addPayloadAttestation, init
from ../../beacon_chain/consensus_object_pools/sync_committee_msg_pool import
  SyncCommitteeMsgPool, init, addSyncCommitteeMessage, addContribution
from ../../beacon_chain/consensus_object_pools/validator_change_pool import
  ValidatorChangePool, init, addMessage
from ../../beacon_chain/fork_choice/fork_choice import on_execution_payload
from ../../beacon_chain/spec/signatures_batch import BatchVerifier, init
from ../testbcutil import addHeadBlock

type
  GossipBlock = object
    name: string
    failed: bool
    pending: bool
    payload: string
    payloadStatus: OptimisticStatus

  GossipMessage = object
    name: string
    time: BeaconTime
    subnetId: uint64
    expected: ValidationResult

  GossipTestMeta = object
    blocks: seq[GossipBlock]
    finalizedEpoch: Opt[Epoch]
    messages: seq[GossipMessage]

const SKIP = [
  # Finalized checkpoint root that is not a known block
  "gossip_beacon_aggregate_and_proof__ignore_finalized_not_ancestor",
  "gossip_beacon_attestation__ignore_finalized_not_ancestor",
  "gossip_beacon_block__reject_finalized_checkpoint_not_ancestor",
  "gossip_data_column_sidecar__reject_non_ancestor_finalized_checkpoint",
  # Gloas state before Gloas fork epoch
  "gossip_proposer_preferences__ignore_pre_gloas_epoch",
  "gossip_proposer_preferences__valid_at_gloas_fork_epoch",
  # Invalid parent's execution payload status is not tracked
  "gossip_beacon_block__reject_parent_consensus_failed_execution_not_verified",
  # Block payload envelope is referenced by meta.yaml but not provided
  "gossip_execution_payload_bid__ignore_parent_block_hash_unknown",
  # Parent state is not advanced to the bid's slot
  "gossip_execution_payload_bid__valid_requires_state_advanced_across_epoch"]

func toValidationResult(expected: string): ValidationResult =
  case expected
  of "valid": ValidationResult.Accept
  of "ignore": ValidationResult.Ignore
  of "reject": ValidationResult.Reject
  else: raiseAssert "Unknown expected outcome: " & expected

proc loadMeta(path: string): GossipTestMeta {.raises: [KeyError, ValueError].} =
  let
    meta = loadToJson(os_ops.readFile(path/"meta.yaml"))[0]
    currentTimeMs =
      if meta.hasKey"current_time_ms": meta["current_time_ms"].getBiggestInt()
      else: 0
  var res: GossipTestMeta
  if meta.hasKey"blocks":
    for blck in meta["blocks"]:
      res.blocks.add GossipBlock(
        name: blck["block"].getStr(),
        failed: blck.hasKey"failed" and blck["failed"].getBool(),
        pending: blck.hasKey"pending" and blck["pending"].getBool(),
        payload: if blck.hasKey"payload": blck["payload"].getStr() else: "",
        payloadStatus:
          if blck.hasKey"payload_status":
            parseEnum[OptimisticStatus](blck["payload_status"].getStr())
          else: OptimisticStatus.valid)
  if meta.hasKey"finalized_checkpoint":
    res.finalizedEpoch =
      Opt.some(Epoch(meta["finalized_checkpoint"]["epoch"].getBiggestInt()))
  for msg in meta["messages"]:
    res.messages.add GossipMessage(
      name: msg["message"].getStr(),
      time: BeaconTime(ns_since_genesis: (
        if msg.hasKey"current_time_ms": msg["current_time_ms"].getBiggestInt()
        elif msg.hasKey"offset_ms":
          currentTimeMs + msg["offset_ms"].getBiggestInt()
        else: currentTimeMs).milliseconds.nanoseconds),
      subnetId:
        if msg.hasKey"subnet_id": msg["subnet_id"].getBiggestInt().uint64
        else: 0,
      expected: msg["expected"].getStr().toValidationResult())
  res

proc initDag(
    path: string, meta: GossipTestMeta,
    consensusFork: static ConsensusFork): ChainDAGRef {.raises: [
      IOError, PresetFileError, PresetIncompatibleError].} =
  let
    cfg =
      if os_ops.fileExists(path/"config.yaml"):
        readRuntimeConfig(path/"config.yaml")[0]
      else:
        consensusFork.genesisTestRuntimeConfig
    db = BeaconChainDB.new("", cfg, inMemory = true)
    state = loadForkedState(path/"state.ssz_snappy", consensusFork)

  let blck = loadBlock(path/meta.blocks[0].name & ".ssz_snappy", consensusFork)
  doAssert blck.message.state_root == state[].root,
    "Anchor block state root must match anchor state"

  withState(state[]):
    db.putBlock(blck.asTrusted())
    db.putState(forkyState.root, forkyState.data)
    db.putStateRoot(blck.root, forkyState.data.slot, forkyState.root)
  db.putHeadBlock(blck.root)
  db.putHeadBlocks(@[blck.root])
  db.putTailBlock(blck.root)

  let validatorMonitor = newClone(ValidatorMonitor.init(cfg))
  ChainDAGRef.init(cfg, db, validatorMonitor, {})

func addBlockRef(dag: ChainDAGRef, root: Eth2Digest, slot: Slot) =
  if dag.getBlockRef(root).isErr():
    dag.forkBlocks.incl(KeyedBlockRef.init(BlockRef.init(dag.cfg, root, slot)))

template gossipTest(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork, MsgType: typedesc,
    setup, validate, accept: untyped) =
  asyncTest $consensusFork & " - " & os_ops.splitPath(path).tail:
    if os_ops.splitPath(path).tail in SKIP:
      skip()
      return
    let
      meta {.inject.} = loadMeta(path)
      dag {.inject, used.} = initDag(path, meta, consensusFork)
      rng = HmacDrbgContext.new()
    var taskpool = Taskpool.new()
    let
      batchCrypto {.inject, used.} = BatchCrypto.new(
        rng, dag.cfg.timeParams, eager = proc(): bool = false,
        genesis_validators_root = dag.genesis_validators_root,
        taskpool).expect("working batcher")
      quarantine {.inject, used.} = newClone(Quarantine.init(dag.cfg))
      envQuarantine {.inject, used.} = newClone(EnvelopeQuarantine.init())
      pool {.inject, used.} = newClone(ValidatorChangePool.init(dag))
      syncCommitteePool {.inject, used.} =
        newClone(SyncCommitteeMsgPool.init(rng, dag.cfg))
    defer:
      dag.db.close()
      batchCrypto.close()
      taskpool.shutdown()

    var
      verifier = BatchVerifier.init(rng, taskpool)
      headRef {.inject.} = dag.head
    for blck in meta.blocks.toOpenArray(1, meta.blocks.high):
      let signedBlock = loadBlock(path/blck.name & ".ssz_snappy", consensusFork)
      if blck.failed:
        check quarantine[].addUnviable(
          signedBlock.root, UnviableKind.Invalid) == UnviableKind.Invalid
      elif blck.pending:
        check quarantine[].addOrphan(dag.finalizedHead.slot, signedBlock).isOk
      else:
        headRef = dag.addHeadBlock(
          verifier, signedBlock, OnBlockAdded[consensusFork](nil),
          blck.payloadStatus).expect("block imports")
        check headRef.root == signedBlock.root
        if blck.payloadStatus == OptimisticStatus.invalidated:
          envQuarantine[].addUnviable(signedBlock.root)
    for blck in meta.blocks:
      if blck.payload.len > 0:
        dag.db.putExecutionPayloadEnvelope(parseTest(
          path/blck.payload & ".ssz_snappy", SSZ,
          SignedExecutionPayloadEnvelope))
    when MsgType is SingleAttestation | electra.SignedAggregateAndProof |
        gloas.SignedAggregateAndProof:
      let attPool {.inject.} = newClone(AttestationPool.init(dag, quarantine))
    setup
    meta.finalizedEpoch.isErrOr:
      when MsgType is gloas.SignedExecutionPayloadBid:
        withState(dag.headState):
          when consensusFork >= ConsensusFork.Gloas:
            forkyState.data.finalized_checkpoint.epoch = value
      else:
        dag.finalizedHead.slot = value.start_slot

    for msg in meta.messages:
      when MsgType is gloas.SignedExecutionPayloadBid:
        if msg.name.startsWith("proposer_preferences_"):
          check dag.validateProposerPreferences(seenPrefs, parseTest(
            path/msg.name & ".ssz_snappy", SSZ, SignedProposerPreferences),
            msg.time).isOk
          continue
        if msg.name.startsWith("execution_payload_envelope_"):
          dag.db.putExecutionPayloadEnvelope(parseTest(
            path/msg.name & ".ssz_snappy", SSZ, SignedExecutionPayloadEnvelope))
          continue
      let
        message {.inject.} =
          try:
            sszDecodeEntireInput(snappy.decode(
              readFileBytes(path/msg.name & ".ssz_snappy"), MaxObjectSize),
              MsgType)
          except SerializationError, UnconsumedInput:
            check msg.expected == ValidationResult.Reject
            continue
        wallTime {.inject, used.} = msg.time
      when MsgType is SyncCommitteeMessage:
        let subcommitteeIdx {.inject.} =
          SyncSubcommitteeIndex.init(msg.subnetId).expect("valid subnet id")
        dag.addBlockRef(message.beacon_block_root, message.slot)
      elif MsgType is SingleAttestation:
        let subnetId {.inject.} = SubnetId(msg.subnetId)
      elif MsgType is fulu.DataColumnSidecar | gloas.DataColumnSidecar:
        let
          subnetId {.inject.} = msg.subnetId
          sidecar {.inject.} = newClone(message)
      elif MsgType is SignedContributionAndProof:
        dag.addBlockRef(
          message.message.contribution.beacon_block_root,
          message.message.contribution.slot)
      elif MsgType is ForkySignedBeaconBlock:
        let signedBlock {.inject.} = MsgType(
          message: message.message, signature: message.signature,
          root: hash_tree_root(message.message))
      let res {.inject.} = validate
      if res.isOk:
        accept

      check (if res.isOk: ValidationResult.Accept else: res.error[0]) ==
        msg.expected

template gossipTest(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork, MsgType: typedesc,
    validate, accept: untyped) =
  gossipTest(
    suiteName, path, consensusFork, MsgType, (discard), validate, accept)

proc runGossipVoluntaryExit(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, SignedVoluntaryExit,
      pool[].validateVoluntaryExit(message, wallTime)):
    pool[].addMessage(message)

proc runGossipProposerSlashing(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, ProposerSlashing,
      pool[].validateProposerSlashing(message)):
    pool[].addMessage(message)

proc runGossipBlsToExecutionChange(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, SignedBLSToExecutionChange,
      await pool[].validateBlsToExecutionChange(
        batchCrypto, message, wallTime.slotOrZero(dag.timeParams).epoch)):
    pool[].addMessage(message, localPriorityMessage = false)

proc runGossipAttesterSlashing(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  when consensusFork >= ConsensusFork.Gloas:
    type AttesterSlashing = gloas.AttesterSlashing
  else:
    type AttesterSlashing = electra.AttesterSlashing
  gossipTest(
      suiteName, path, consensusFork, AttesterSlashing,
      pool[].validateAttesterSlashing(message)):
    pool[].addMessage(message)

proc runGossipSyncCommitteeMessage(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, SyncCommitteeMessage,
      await dag.validateSyncCommitteeMessage(
        quarantine, batchCrypto, syncCommitteePool, message,
        subcommitteeIdx, wallTime, checkSignature = true)):
    let (bid, sig, positions) = res.get()
    syncCommitteePool[].addSyncCommitteeMessage(
      message.slot, bid, message.validator_index, sig, subcommitteeIdx,
      positions)

proc runGossipSyncCommitteeContribution(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, SignedContributionAndProof,
      await dag.validateContribution(
        quarantine, batchCrypto, syncCommitteePool, message, wallTime,
        checkSignature = true)):
    let (bid, sig, _) = res.get()
    syncCommitteePool[].addContribution(message, bid, sig)

proc runGossipPayloadAttestationMessage(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, PayloadAttestationMessage,
      (let ptcPool = newClone(PayloadAttestationPool.init(dag))),
      await dag.validatePayloadAttestationMessage(
        quarantine, ptcPool, batchCrypto, message, wallTime)):
    check ptcPool[].addPayloadAttestation(message, wallTime)

proc runGossipExecutionPayloadEnvelope(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, SignedExecutionPayloadEnvelope,
      dag.validateExecutionPayload(
        quarantine, envQuarantine, message, wallTime)):
    dag.db.putExecutionPayloadEnvelope(message)

proc runGossipBeaconAttestation(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, SingleAttestation,
      await attPool.validateAttestation(
        batchCrypto, envQuarantine, message, wallTime, subnetId,
        checkSignature = true)):
    let (attesterIndex, committeeLen, indexInCommittee, sig) = res.get()
    attPool[].addAttestation(
      message, [attesterIndex], committeeLen, indexInCommittee, sig, wallTime)

proc runGossipBeaconAggregateAndProof(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  when consensusFork >= ConsensusFork.Gloas:
    type SignedAggregateAndProof = gloas.SignedAggregateAndProof
  else:
    type SignedAggregateAndProof = electra.SignedAggregateAndProof
  gossipTest(
      suiteName, path, consensusFork, SignedAggregateAndProof,
      await attPool.validateAggregate(
        batchCrypto, envQuarantine, message, wallTime)):
    template aggregate: untyped = message.message.aggregate
    let (attestingIndices, sig) = res.get()
    attPool[].addAttestation(
      aggregate, attestingIndices, aggregate.aggregation_bits.len, -1, sig,
      wallTime)

proc runGossipDataColumnSidecar(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  when consensusFork >= ConsensusFork.Gloas:
    gossipTest(
        suiteName, path, consensusFork, gloas.DataColumnSidecar, (
          let
            colQuarantine = newClone(GloasColumnQuarantine.init(
              dag.cfg, toSeq(ColumnIndex(0) ..< ColumnIndex(NUMBER_OF_COLUMNS)),
              dag.db.getQuarantineDB(), 10, nil))
            bidPool = newClone(ExecutionPayloadBidPool.init(dag))),
        await dag.validateDataColumnSidecar(
          batchCrypto, quarantine, colQuarantine, bidPool, sidecar,
          wallTime, subnetId)):
      colQuarantine[].put(
        sidecar[].beacon_block_root, sidecar, verified = true)
  else:
    gossipTest(
        suiteName, path, consensusFork, fulu.DataColumnSidecar,
        (let colQuarantine = newClone(FuluColumnQuarantine.init(
          dag.cfg, toSeq(ColumnIndex(0) ..< ColumnIndex(NUMBER_OF_COLUMNS)),
          dag.db.getQuarantineDB(), 10, nil))),
        await dag.validateDataColumnSidecar(
          batchCrypto, quarantine, colQuarantine, sidecar, wallTime,
          subnetId)):
      colQuarantine[].put(
        hash_tree_root(sidecar[].signed_block_header.message), sidecar,
        verified = true)

proc runGossipBeaconBlock(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, consensusFork.SignedBeaconBlock,
      dag.validateBeaconBlock(
        quarantine, envQuarantine, signedBlock, wallTime, {})):
    dag.addBlockRef(signedBlock.root, signedBlock.message.slot)

proc runGossipProposerPreferences(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  gossipTest(
      suiteName, path, consensusFork, SignedProposerPreferences,
      (var seenPrefs: SeenProposerPreferences),
      dag.validateProposerPreferences(seenPrefs, message, wallTime)):
    check dag.validateProposerPreferences(
      seenPrefs, message, wallTime).error[0] == ValidationResult.Ignore

template bidAttestationPool(
    dag: ChainDAGRef, meta: GossipTestMeta, path: string, headRef: BlockRef,
    quarantine: ref Quarantine): ref AttestationPool =
  dag.updateHead(headRef, quarantine[], [])
  dag.updateHeadExecutionPayload(
    dag.db.containsExecutionPayloadEnvelope(headRef.root), true)
  let pool = newClone(
    AttestationPool.init(dag, quarantine, meta.messages[0].time))
  for blck in meta.blocks:
    if blck.payload.len > 0:
      check pool.forkChoice.on_execution_payload(
        dag.cfg, dag.timeParams, parseTest(
          path/blck.payload & ".ssz_snappy", SSZ,
          SignedExecutionPayloadEnvelope)).isOk
  pool

proc runGossipExecutionPayloadBid(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  debugHezeComment "Heze `SignedExecutionPayloadBid` adds `inclusion_list_bits`"
  when consensusFork == ConsensusFork.Gloas:
    gossipTest(
        suiteName, path, consensusFork, gloas.SignedExecutionPayloadBid, (
          let
            attPool = dag.bidAttestationPool(meta, path, headRef, quarantine)
            bidPool = newClone(ExecutionPayloadBidPool.init(dag))
          var seenPrefs: SeenProposerPreferences),
        dag.validateExecutionPayloadBid(
          attPool.forkChoice, bidPool, seenPrefs, message, wallTime)):
      bidPool[].addBid(message, res.get(), wallTime)

proc runGossipInclusionList(
    suiteName: static string, path: string,
    consensusFork: static ConsensusFork) =
  when consensusFork >= ConsensusFork.Heze:
    gossipTest(
        suiteName, path, consensusFork, SignedInclusionList, (
          dag.updateHead(headRef, quarantine[], []);
          let ilPool = newClone(InclusionListPool.init(dag.cfg))),
        await dag.validateInclusionList(
          ilPool, batchCrypto, message, wallTime)):
      check ilPool[].addInclusionList(message, is_timely = true, wallTime)

template gossipSuite(
    topic: static[string], handler: static[string], runner: untyped) =
  const name = "EF - Networking - Gossip - " & topic & preset()
  suite name:
    const presetPath = SszTestsDir/const_preset
    for kind, path in walkDir(presetPath, relative = true, checkDir = true):
      let testsPath = presetPath/path/"networking"/handler/"pyspec_tests"
      if kind != pcDir or not os_ops.dirExists(testsPath):
        continue
      let fork = forkForPathComponent(path).valueOr:
        raiseAssert "Unknown test fork: " & testsPath
      withConsensusFork(fork):
        when consensusFork >= ConsensusFork.Fulu:
          for kind, path in walkDir(
              testsPath, relative = true, checkDir = true):
            if kind != pcDir:
              continue
            runner(name, testsPath/path, consensusFork)

gossipSuite(
  "Voluntary Exit", "gossip_voluntary_exit", runGossipVoluntaryExit)
gossipSuite(
  "Proposer Slashing", "gossip_proposer_slashing", runGossipProposerSlashing)
gossipSuite(
  "Attester Slashing", "gossip_attester_slashing", runGossipAttesterSlashing)
gossipSuite(
  "BLS To Execution Change", "gossip_bls_to_execution_change",
  runGossipBlsToExecutionChange)
gossipSuite(
  "Sync Committee Message", "gossip_sync_committee_message",
  runGossipSyncCommitteeMessage)
gossipSuite(
  "Sync Committee Contribution And Proof",
  "gossip_sync_committee_contribution_and_proof",
  runGossipSyncCommitteeContribution)
gossipSuite(
  "Payload Attestation Message", "gossip_payload_attestation_message",
  runGossipPayloadAttestationMessage)
gossipSuite(
  "Execution Payload Envelope", "gossip_execution_payload_envelope",
  runGossipExecutionPayloadEnvelope)
gossipSuite(
  "Proposer Preferences", "gossip_proposer_preferences",
  runGossipProposerPreferences)
gossipSuite(
  "Beacon Attestation", "gossip_beacon_attestation",
  runGossipBeaconAttestation)
gossipSuite(
  "Beacon Aggregate And Proof", "gossip_beacon_aggregate_and_proof",
  runGossipBeaconAggregateAndProof)
gossipSuite(
  "Data Column Sidecar", "gossip_data_column_sidecar",
  runGossipDataColumnSidecar)
gossipSuite(
  "Beacon Block", "gossip_beacon_block", runGossipBeaconBlock)
gossipSuite(
  "Execution Payload Bid", "gossip_execution_payload_bid",
  runGossipExecutionPayloadBid)
gossipSuite(
  "Inclusion List", "gossip_inclusion_list", runGossipInclusionList)
