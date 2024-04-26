# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
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
  stew/results,
  # Beacon chain internals
  ../../../beacon_chain/spec/state_transition_block,
  ../../../beacon_chain/spec/datatypes/electra,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops,
  ../../helpers/debug_state

from std/sequtils import mapIt, toSeq
#from std/strutils import contains
from ../../../beacon_chain/spec/beaconstate import
  get_base_reward_per_increment, get_state_exit_queue_info,
  get_total_active_balance, process_attestation

const
  OpDir                     = SszTestsDir/const_preset/"electra"/"operations"
  OpAttestationsDir         = OpDir/"attestation"
  OpAttSlashingDir          = OpDir/"attester_slashing"
  OpBlockHeaderDir          = OpDir/"block_header"
  OpBlsToExecutionChangeDir = OpDir/"bls_to_execution_change"
  OpConsolidationDir        = OpDir/"consolidation"
  OpDepositReceiptDir       = OpDir/"deposit_receipt"
  OpDepositsDir             = OpDir/"deposit"
  OpExecutionLayerWithdrawalRequestDir = OpDir/"execution_layer_withdrawal_request"
  OpExecutionPayloadDir     = OpDir/"execution_payload"
  OpProposerSlashingDir     = OpDir/"proposer_slashing"
  OpSyncAggregateDir        = OpDir/"sync_aggregate"
  OpVoluntaryExitDir        = OpDir/"voluntary_exit"
  OpWithdrawalsDir          = OpDir/"withdrawals"

  baseDescription = "EF - Electra - Operations - "

doAssert toHashSet(mapIt(toSeq(walkDir(OpDir, relative = false)), it.path)) ==
  toHashSet([
    OpAttestationsDir, OpAttSlashingDir, OpBlockHeaderDir,
    OpBlsToExecutionChangeDir, OpConsolidationDir, OpDepositReceiptDir,
    OpDepositsDir, OpExecutionLayerWithdrawalRequestDir,
    OpExecutionPayloadDir, OpProposerSlashingDir, OpSyncAggregateDir,
    OpVoluntaryExitDir, OpWithdrawalsDir])

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
      parseTest(testDir/"pre.ssz_snappy", SSZ, electra.BeaconState))
    let done = applyProc(
      preState[], parseTest(testDir/(applyFile & ".ssz_snappy"), SSZ, T))

    if fileExists(testDir/"post.ssz_snappy"):
      let postState =
        newClone(parseTest(
          testDir/"post.ssz_snappy", SSZ, electra.BeaconState))

      reportDiff(preState, postState)
      check:
        done.isOk()
        preState[].hash_tree_root() == postState[].hash_tree_root()
    else:
      check: done.isErr() # No post state = processing should fail

when false:
  debugRaiseAssert "when these are fixed..."
  suite baseDescription & "Attestation " & preset():
    func applyAttestation(
        preState: var electra.BeaconState, attestation: Attestation):
        Result[void, cstring] =
      var cache: StateCache
      let
        total_active_balance = get_total_active_balance(preState, cache)
        base_reward_per_increment =
          get_base_reward_per_increment(total_active_balance)

      # This returns the proposer reward for including the attestation, which
      # isn't tested here.
      discard ? process_attestation(
        preState, attestation, {strictVerification}, base_reward_per_increment, cache)
      ok()

    for path in walkTests(OpAttestationsDir):
      runTest[Attestation, typeof applyAttestation](
        OpAttestationsDir, suiteName, "Attestation", "attestation",
        applyAttestation, path)

suite baseDescription & "Attester Slashing " & preset():
  proc applyAttesterSlashing(
      preState: var electra.BeaconState,
      attesterSlashing: ElectraAttesterSlashing): Result[void, cstring] =
    var cache: StateCache
    doAssert (? process_attester_slashing(
      defaultRuntimeConfig, preState, attesterSlashing, {},
      get_state_exit_queue_info(preState), cache))[0] > 0.Gwei
    ok()

  for path in walkTests(OpAttSlashingDir):
    runTest[ElectraAttesterSlashing, typeof applyAttesterSlashing](
      OpAttSlashingDir, suiteName, "Attester Slashing", "attester_slashing",
      applyAttesterSlashing, path)

suite baseDescription & "Block Header " & preset():
  func applyBlockHeader(
      preState: var electra.BeaconState, blck: electra.BeaconBlock):
      Result[void, cstring] =
    var cache: StateCache
    process_block_header(preState, blck, {}, cache)

  for path in walkTests(OpBlockHeaderDir):
    runTest[electra.BeaconBlock, typeof applyBlockHeader](
      OpBlockHeaderDir, suiteName, "Block Header", "block",
      applyBlockHeader, path)

from ../../../beacon_chain/spec/datatypes/capella import
  SignedBLSToExecutionChange

suite baseDescription & "BLS to execution change " & preset():
  proc applyBlsToExecutionChange(
      preState: var electra.BeaconState,
      signed_address_change: SignedBLSToExecutionChange):
      Result[void, cstring] =
    process_bls_to_execution_change(
      defaultRuntimeConfig, preState, signed_address_change)

  for path in walkTests(OpBlsToExecutionChangeDir):
    runTest[SignedBLSToExecutionChange, typeof applyBlsToExecutionChange](
      OpBlsToExecutionChangeDir, suiteName, "BLS to execution change", "address_change",
      applyBlsToExecutionChange, path)

suite baseDescription & "Consolidation " & preset():
  func applyConsolidation(
      preState: var electra.BeaconState,
      signed_consolidation: SignedConsolidation):
      Result[void, cstring] =
    var cache: StateCache
    process_consolidation(
      defaultRuntimeConfig, preState, signed_consolidation, cache)

  for path in walkTests(OpConsolidationDir):
    if path in [
        "multiple_consolidations_below_churn",  # missing consolidation.ssz
        "multiple_consolidations_equal_churn",  # missing consolidation.ssz
        "multiple_consolidations_equal_twice_churn",  # missing consolidation.ssz
        "invalid_exceed_pending_consolidations_limit",    # apparently invalid prestate SSZ
        ]:
      continue
    runTest[SignedConsolidation, typeof applyConsolidation](
      OpConsolidationDir, suiteName, "Consolidation", "consolidation",
      applyConsolidation, path)

from ".."/".."/".."/beacon_chain/bloomfilter import constructBloomFilter

suite baseDescription & "Deposit " & preset():
  func applyDeposit(
      preState: var electra.BeaconState, deposit: Deposit):
      Result[void, cstring] =
    process_deposit(
      defaultRuntimeConfig, preState,
      constructBloomFilter(preState.validators.asSeq)[], deposit, {})

  for path in walkTests(OpDepositsDir):
    runTest[Deposit, typeof applyDeposit](
      OpDepositsDir, suiteName, "Deposit", "deposit", applyDeposit, path)

suite baseDescription & "Deposit Receipt" & preset():
  func applyDepositReceipt(
      preState: var electra.BeaconState, depositReceipt: DepositReceipt):
      Result[void, cstring] =
    process_deposit_receipt(
      defaultRuntimeConfig, preState,
      constructBloomFilter(preState.validators.asSeq)[], depositReceipt, {})

  for path in walkTests(OpDepositReceiptDir):
    runTest[DepositReceipt, typeof applyDepositReceipt](
      OpDepositReceiptDir, suiteName, "Deposit Receipt", "deposit_receipt",
      applyDepositReceipt, path)

when false:
  suite baseDescription & "Execution Payload " & preset():
    func makeApplyExecutionPayloadCb(path: string): auto =
      return proc(
          preState: var electra.BeaconState, body: electra.BeaconBlockBody):
          Result[void, cstring] {.raises: [IOError].} =
        let payloadValid = os_ops.readFile(
            OpExecutionPayloadDir/"pyspec_tests"/path/"execution.yaml"
          ).contains("execution_valid: true")
        func executePayload(_: electra.ExecutionPayload): bool = payloadValid
        process_execution_payload(preState, body, executePayload)

    for path in walkTests(OpExecutionPayloadDir):
      let applyExecutionPayload = makeApplyExecutionPayloadCb(path)
      runTest[electra.BeaconBlockBody, typeof applyExecutionPayload](
        OpExecutionPayloadDir, suiteName, "Execution Payload", "body",
        applyExecutionPayload, path)

suite baseDescription & "Execution Layer Withdrawal Request " & preset():
  func applyExecutionLayerWithdrawalRequest(
      preState: var electra.BeaconState,
      executionLayerWithdrawalRequest: ExecutionLayerWithdrawalRequest):
      Result[void, cstring] =
    var cache: StateCache
    process_execution_layer_withdrawal_request(
      defaultRuntimeConfig, preState, executionLayerWithdrawalRequest, cache)
    ok()

  for path in walkTests(OpExecutionLayerWithdrawalRequestDir):
    runTest[ExecutionLayerWithdrawalRequest,
            typeof applyExecutionLayerWithdrawalRequest](
      OpExecutionLayerWithdrawalRequestDir, suiteName,
      "Execution Layer Withdrawal Request",
      "execution_layer_withdrawal_request",
      applyExecutionLayerWithdrawalRequest, path)

suite baseDescription & "Proposer Slashing " & preset():
  proc applyProposerSlashing(
      preState: var electra.BeaconState, proposerSlashing: ProposerSlashing):
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
      preState: var electra.BeaconState, syncAggregate: SyncAggregate):
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
      preState: var electra.BeaconState, voluntaryExit: SignedVoluntaryExit):
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
      preState: var electra.BeaconState,
      executionPayload: electra.ExecutionPayload): Result[void, cstring] =
    process_withdrawals(preState, executionPayload)

  for path in walkTests(OpWithdrawalsDir):
    runTest[electra.ExecutionPayload, typeof applyWithdrawals](
      OpWithdrawalsDir, suiteName, "Withdrawals", "execution_payload",
      applyWithdrawals, path)