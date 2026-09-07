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
  ../../beacon_chain/consensus_object_pools/blockchain_dag,
  ../../beacon_chain/gossip_processing/[batch_validation, gossip_validation],
  ../testutil,
  ./fixtures_utils, ./os_ops

from std/json import
  JsonNode, getBiggestInt, getBool, getStr, hasKey, items, len, `[]`
from chronos/unittest2/asynctests import asyncTest
from libp2p/protocols/pubsub/errors import ValidationResult
from snappy import decode
from ../../beacon_chain/consensus_object_pools/block_clearance import
  checkHeadBlock
from ../../beacon_chain/consensus_object_pools/block_quarantine import
  Quarantine, UnviableKind, addUnviable, init
from ../../beacon_chain/consensus_object_pools/envelope_quarantine import
  EnvelopeQuarantine, init
from ../../beacon_chain/consensus_object_pools/payload_attestation_pool import
  PayloadAttestationPool, addPayloadAttestation, init
from ../../beacon_chain/consensus_object_pools/sync_committee_msg_pool import
  SyncCommitteeMsgPool, init, addSyncCommitteeMessage, addContribution
from ../../beacon_chain/consensus_object_pools/validator_change_pool import
  ValidatorChangePool, init, addMessage
from ../../beacon_chain/spec/signatures_batch import BatchVerifier, init
from ../testbcutil import addHeadBlock

type
  GossipBlock = object
    name: string
    failed: bool

  GossipMessage = object
    name: string
    time: BeaconTime
    subnetId: uint64
    expected: ValidationResult

  GossipTestMeta = object
    blocks: seq[GossipBlock]
    finalizedEpoch: Opt[Epoch]
    messages: seq[GossipMessage]

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
        failed: blck.hasKey"failed" and blck["failed"].getBool())
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
    consensusFork: static ConsensusFork): ChainDAGRef =
  let
    cfg = consensusFork.genesisTestRuntimeConfig
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
    validate, accept: untyped) =
  asyncTest $consensusFork & " - " & os_ops.splitPath(path).tail:
    let
      meta = loadMeta(path)
      dag {.inject, used.} = initDag(path, meta, consensusFork)
      rng = HmacDrbgContext.new()
      taskpool = Taskpool.new()
      batchCrypto {.inject, used.} = BatchCrypto.new(
        rng, dag.cfg.timeParams, eager = proc(): bool = false,
        genesis_validators_root = dag.genesis_validators_root,
        taskpool).expect("working batcher")
      quarantine {.inject, used.} = newClone(Quarantine.init(dag.cfg))
      envQuarantine {.inject, used.} = newClone(EnvelopeQuarantine.init())
      pool {.inject, used.} = newClone(ValidatorChangePool.init(dag))
      syncCommitteePool {.inject, used.} =
        newClone(SyncCommitteeMsgPool.init(rng, dag.cfg))
      ptcPool {.inject, used.} =
        newClone(PayloadAttestationPool.init(dag))
    defer: dag.db.close()

    var verifier = BatchVerifier.init(rng, taskpool)
    for blck in meta.blocks.toOpenArray(1, meta.blocks.high):
      let signedBlock = loadBlock(path/blck.name & ".ssz_snappy", consensusFork)
      if blck.failed:
        check quarantine[].addUnviable(
          signedBlock.root, UnviableKind.Invalid) == UnviableKind.Invalid
      else:
        check dag.addHeadBlock(
          verifier, signedBlock, OnBlockAdded[consensusFork](nil)).expect(
            "block imports").root == signedBlock.root
    if meta.finalizedEpoch.isSome:
      dag.finalizedHead.slot = meta.finalizedEpoch.get.start_slot

    for msg in meta.messages:
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
        subcommitteeIdx {.inject, used.} =
          SyncSubcommitteeIndex.init(msg.subnetId).expect("valid subnet id")
      when MsgType is SyncCommitteeMessage:
        dag.addBlockRef(message.beacon_block_root, message.slot)
      elif MsgType is SignedContributionAndProof:
        dag.addBlockRef(
          message.message.contribution.beacon_block_root,
          message.message.contribution.slot)
      let res {.inject.} = validate
      if res.isOk:
        accept

      check (if res.isOk: ValidationResult.Accept else: res.error[0]) ==
        msg.expected

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
