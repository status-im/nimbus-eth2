# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Utilities
  chronicles,
  unittest2,
  # Beacon chain internals
  ../../../beacon_chain/spec/state_transition_block,
  ../../../beacon_chain/spec/datatypes/capella,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops,
  ../../helpers/debug_state

from std/sequtils import mapIt, toSeq
from std/strutils import contains
from ../../../beacon_chain/spec/beaconstate import
  get_base_reward_per_increment, get_state_exit_queue_info,
  get_total_active_balance, process_attestation

const
  OpDir                     = SszTestsDir/const_preset/"capella"/"operations"
  OpAttestationsDir         = OpDir/"attestation"
  OpAttSlashingDir          = OpDir/"attester_slashing"
  OpBlockHeaderDir          = OpDir/"block_header"
  OpBlsToExecutionChangeDir = OpDir/"bls_to_execution_change"
  OpDepositsDir             = OpDir/"deposit"
  OpExecutionPayloadDir     = OpDir/"execution_payload"
  OpProposerSlashingDir     = OpDir/"proposer_slashing"
  OpSyncAggregateDir        = OpDir/"sync_aggregate"
  OpVoluntaryExitDir        = OpDir/"voluntary_exit"
  OpWithdrawalsDir          = OpDir/"withdrawals"

  baseDescription = "EF - Capella - Operations - "

doAssert toHashSet(mapIt(toSeq(walkDir(OpDir, relative = false)), it.path)) ==
  toHashSet([
    OpAttestationsDir, OpAttSlashingDir, OpBlockHeaderDir,
    OpBlsToExecutionChangeDir, OpDepositsDir, OpExecutionPayloadDir,
    OpProposerSlashingDir, OpSyncAggregateDir, OpVoluntaryExitDir,
    OpWithdrawalsDir])

proc runTest[T, U](
    testSuiteDir, suiteName, opName, applyFile: string,
    applyProc: U, identifier: string) =
  let testDir = testSuiteDir / "pyspec_tests" / identifier

  let prefix =
    if fileExists(testDir/"post.ssz_snappy"):
      "[Valid]   "
    else:
      "[Invalid] "

  test prefix & baseDescription & opName & " - " & identifier:
    let preState = newClone(
      parseTest(testDir/"pre.ssz_snappy", SSZ, capella.BeaconState))
    let done = applyProc(
      preState[], parseTest(testDir/(applyFile & ".ssz_snappy"), SSZ, T))

    if fileExists(testDir/"post.ssz_snappy"):
      let postState =
        newClone(parseTest(
          testDir/"post.ssz_snappy", SSZ, capella.BeaconState))

      reportDiff(preState, postState)
      check:
        done.isOk()
        preState[].hash_tree_root() == postState[].hash_tree_root()
    else:
      check: done.isErr() # No post state = processing should fail

suite baseDescription & "Attestation " & preset():
  proc applyAttestation(
      preState: var capella.BeaconState, attestation: phase0.Attestation):
      Result[void, cstring] =
    var cache: StateCache
    let
      total_active_balance = get_total_active_balance(preState, cache)
      base_reward_per_increment =
        get_base_reward_per_increment(total_active_balance)

    # This returns the proposer reward for including the attestation, which
    # isn't tested here.
    discard ? process_attestation(
      preState, attestation, {}, base_reward_per_increment, cache)
    ok()

  for path in walkTests(OpAttestationsDir):
    runTest[phase0.Attestation, typeof applyAttestation](
      OpAttestationsDir, suiteName, "Attestation", "attestation",
      applyAttestation, path)

suite baseDescription & "Attester Slashing " & preset():
  proc applyAttesterSlashing(
      preState: var capella.BeaconState,
      attesterSlashing: phase0.AttesterSlashing): Result[void, cstring] =
    var cache: StateCache
    doAssert (? process_attester_slashing(
      defaultRuntimeConfig, preState, attesterSlashing, {strictVerification},
      get_state_exit_queue_info(preState), cache))[0] > 0.Gwei
    ok()

  for path in walkTests(OpAttSlashingDir):
    runTest[phase0.AttesterSlashing, typeof applyAttesterSlashing](
      OpAttSlashingDir, suiteName, "Attester Slashing", "attester_slashing",
      applyAttesterSlashing, path)

suite baseDescription & "Block Header " & preset():
  func applyBlockHeader(
      preState: var capella.BeaconState, blck: capella.BeaconBlock):
      Result[void, cstring] =
    var cache: StateCache
    process_block_header(preState, blck, {}, cache)

  for path in walkTests(OpBlockHeaderDir):
    runTest[capella.BeaconBlock, typeof applyBlockHeader](
      OpBlockHeaderDir, suiteName, "Block Header", "block",
      applyBlockHeader, path)

suite baseDescription & "BLS to execution change " & preset():
  proc applyBlsToExecutionChange(
      preState: var capella.BeaconState,
      signed_address_change: SignedBLSToExecutionChange):
      Result[void, cstring] =
    process_bls_to_execution_change(
      defaultRuntimeConfig, preState, signed_address_change)

  for path in walkTests(OpBlsToExecutionChangeDir):
    runTest[SignedBLSToExecutionChange, typeof applyBlsToExecutionChange](
      OpBlsToExecutionChangeDir, suiteName, "BLS to execution change", "address_change",
      applyBlsToExecutionChange, path)

from ".."/".."/".."/beacon_chain/bloomfilter import constructBloomFilter

suite baseDescription & "Deposit " & preset():
  func applyDeposit(
      preState: var capella.BeaconState, deposit: Deposit):
      Result[void, cstring] =
    process_deposit(
      defaultRuntimeConfig, preState,
      constructBloomFilter(preState.validators.asSeq)[], deposit, {})

  for path in walkTests(OpDepositsDir):
    runTest[Deposit, typeof applyDeposit](
      OpDepositsDir, suiteName, "Deposit", "deposit", applyDeposit, path)

suite baseDescription & "Execution Payload " & preset():
  func makeApplyExecutionPayloadCb(path: string): auto =
    return proc(
        preState: var capella.BeaconState, body: capella.BeaconBlockBody):
        Result[void, cstring] {.raises: [IOError].} =
      let payloadValid = os_ops.readFile(
          OpExecutionPayloadDir/"pyspec_tests"/path/"execution.yaml"
        ).contains("execution_valid: true")
      func executePayload(_: capella.ExecutionPayload): bool = payloadValid
      process_execution_payload(
        preState, body.execution_payload, executePayload)

  for path in walkTests(OpExecutionPayloadDir):
    let applyExecutionPayload = makeApplyExecutionPayloadCb(path)
    runTest[capella.BeaconBlockBody, typeof applyExecutionPayload](
      OpExecutionPayloadDir, suiteName, "Execution Payload", "body",
      applyExecutionPayload, path)

suite baseDescription & "Proposer Slashing " & preset():
  proc applyProposerSlashing(
      preState: var capella.BeaconState, proposerSlashing: ProposerSlashing):
      Result[void, cstring] =
    var cache: StateCache
    doAssert (? process_proposer_slashing(
      defaultRuntimeConfig, preState, proposerSlashing, {},
      get_state_exit_queue_info(preState), cache))[0] > 0.Gwei
    ok()

  for path in walkTests(OpProposerSlashingDir):
    runTest[ProposerSlashing, typeof applyProposerSlashing](
      OpProposerSlashingDir, suiteName, "Proposer Slashing", "proposer_slashing",
      applyProposerSlashing, path)

suite baseDescription & "Sync Aggregate " & preset():
  proc applySyncAggregate(
      preState: var capella.BeaconState, syncAggregate: SyncAggregate):
      Result[void, cstring] =
    var cache: StateCache
    doAssert (? process_sync_aggregate(
      preState, syncAggregate, get_total_active_balance(preState, cache),
      {}, cache)) > 0.Gwei
    ok()

  for path in walkTests(OpSyncAggregateDir):
    runTest[SyncAggregate, typeof applySyncAggregate](
      OpSyncAggregateDir, suiteName, "Sync Aggregate", "sync_aggregate",
      applySyncAggregate, path)

suite baseDescription & "Voluntary Exit " & preset():
  proc applyVoluntaryExit(
      preState: var capella.BeaconState, voluntaryExit: SignedVoluntaryExit):
      Result[void, cstring] =
    var cache: StateCache
    if process_voluntary_exit(
        defaultRuntimeConfig, preState, voluntaryExit, {},
        get_state_exit_queue_info(preState), cache).isOk:
      ok()
    else:
      err("")

  for path in walkTests(OpVoluntaryExitDir):
    runTest[SignedVoluntaryExit, typeof applyVoluntaryExit](
      OpVoluntaryExitDir, suiteName, "Voluntary Exit", "voluntary_exit",
      applyVoluntaryExit, path)

suite baseDescription & "Withdrawals " & preset():
  func applyWithdrawals(
      preState: var capella.BeaconState,
      executionPayload: capella.ExecutionPayload): Result[void, cstring] =
    process_withdrawals(preState, executionPayload)

  for path in walkTests(OpWithdrawalsDir):
    runTest[capella.ExecutionPayload, typeof applyWithdrawals](
      OpWithdrawalsDir, suiteName, "Withdrawals", "execution_payload",
      applyWithdrawals, path)