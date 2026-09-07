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
  JsonNode, getBiggestInt, getStr, hasKey, items, len, `[]`
from chronos/unittest2/asynctests import asyncTest
from libp2p/protocols/pubsub/errors import ValidationResult
from ../../beacon_chain/consensus_object_pools/validator_change_pool import
  ValidatorChangePool, init, addMessage

type
  GossipMessage = object
    name: string
    time: BeaconTime
    expected: ValidationResult

  GossipTestMeta = object
    blocks: seq[string]
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
      res.blocks.add blck["block"].getStr()
  for msg in meta["messages"]:
    res.messages.add GossipMessage(
      name: msg["message"].getStr(),
      time: BeaconTime(ns_since_genesis:
        (currentTimeMs + (
          if msg.hasKey"offset_ms": msg["offset_ms"].getBiggestInt()
          else: 0)).milliseconds.nanoseconds),
      expected: msg["expected"].getStr().toValidationResult())
  res

proc initDag(
    path: string, meta: GossipTestMeta,
    consensusFork: static ConsensusFork): ChainDAGRef =
  let
    cfg = consensusFork.genesisTestRuntimeConfig
    db = BeaconChainDB.new("", cfg, inMemory = true)
    state = loadForkedState(path/"state.ssz_snappy", consensusFork)

  doAssert meta.blocks.len == 1, "Only a single anchor block is supported"
  let blck = loadBlock(path/meta.blocks[0] & ".ssz_snappy", consensusFork)
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

template validatorChangeTest(
    suiteName, path: string, consensusFork: static ConsensusFork,
    MsgType: typedesc, validate: untyped) =
  asyncTest $consensusFork & " - " & os_ops.splitPath(path).tail:
    let
      meta = loadMeta(path)
      dag {.inject, used.} = initDag(path, meta, consensusFork)
      pool {.inject.} = newClone(ValidatorChangePool.init(dag))
      rng = HmacDrbgContext.new()
      taskpool = Taskpool.new()
      batchCrypto {.inject, used.} = BatchCrypto.new(
        rng, dag.cfg.timeParams, eager = proc(): bool = false,
        genesis_validators_root = dag.genesis_validators_root, taskpool).expect(
          "working batcher")
    defer: dag.db.close()

    for msg in meta.messages:
      let
        message {.inject.} = parseTest(
          path/msg.name & ".ssz_snappy", SSZ, MsgType)
        wallTime {.inject, used.} = msg.time
        res = validate
      if res.isOk:
        when MsgType is SignedBLSToExecutionChange:
          pool[].addMessage(message, localPriorityMessage = false)
        else:
          pool[].addMessage(message)

      check (if res.isOk: ValidationResult.Accept else: res.error[0]) ==
        msg.expected

proc runGossipVoluntaryExit(
    suiteName, path: string, consensusFork: static ConsensusFork) =
  validatorChangeTest(
    suiteName, path, consensusFork, SignedVoluntaryExit,
    pool[].validateVoluntaryExit(message, wallTime))

proc runGossipProposerSlashing(
    suiteName, path: string, consensusFork: static ConsensusFork) =
  validatorChangeTest(
    suiteName, path, consensusFork, ProposerSlashing,
    pool[].validateProposerSlashing(message))

proc runGossipBlsToExecutionChange(
    suiteName, path: string, consensusFork: static ConsensusFork) =
  validatorChangeTest(
    suiteName, path, consensusFork, SignedBLSToExecutionChange,
    await pool[].validateBlsToExecutionChange(
      batchCrypto, message, wallTime.slotOrZero(dag.timeParams).epoch))

proc runGossipAttesterSlashing(
    suiteName, path: string, consensusFork: static ConsensusFork) =
  when consensusFork >= ConsensusFork.Gloas:
    type AttesterSlashing = gloas.AttesterSlashing
  else:
    type AttesterSlashing = electra.AttesterSlashing
  validatorChangeTest(
    suiteName, path, consensusFork, AttesterSlashing,
    pool[].validateAttesterSlashing(message))

template gossipSuite(
    suiteName: static[string], handler: static[string], runner: untyped) =
  suite suiteName:
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
            runner(suiteName, testsPath/path, consensusFork)
        else:
          discard

gossipSuite(
  "EF - Networking - Gossip - Voluntary Exit" & preset(),
  "gossip_voluntary_exit", runGossipVoluntaryExit)
gossipSuite(
  "EF - Networking - Gossip - Proposer Slashing" & preset(),
  "gossip_proposer_slashing", runGossipProposerSlashing)
gossipSuite(
  "EF - Networking - Gossip - Attester Slashing" & preset(),
  "gossip_attester_slashing", runGossipAttesterSlashing)
gossipSuite(
  "EF - Networking - Gossip - BLS To Execution Change" & preset(),
  "gossip_bls_to_execution_change", runGossipBlsToExecutionChange)
