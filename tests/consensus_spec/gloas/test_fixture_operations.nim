# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  # Utilities
  chronicles,
  unittest2,
  # Beacon chain internals
  ../../../beacon_chain/spec/state_transition_block,
  ../../../beacon_chain/spec/datatypes/gloas,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops,
  ../../helpers/debug_state

from std/sequtils import anyIt, mapIt, toSeq
from std/strutils import contains
from ../../../beacon_chain/spec/beaconstate import
  get_base_reward_per_increment, get_state_exit_queue_info,
  get_total_active_balance, latest_block_root, process_attestation

const
  OpDir                       = SszTestsDir/const_preset/"gloas"/"operations"
  OpAttestationsDir           = OpDir/"attestation"
  OpAttSlashingDir            = OpDir/"attester_slashing"
  OpBlockHeaderDir            = OpDir/"block_header"
  OpBlsToExecutionChangeDir   = OpDir/"bls_to_execution_change"
  OpConsolidationRequestDir   = OpDir/"consolidation_request"
  OpDepositRequestDir         = OpDir/"deposit_request"
  OpDepositsDir               = OpDir/"deposit"
  OpWithdrawalRequestDir      = OpDir/"withdrawal_request"
  OpExecutionPayloadDir       = OpDir/"execution_payload"
  OpExecutionPayloadBidDir    = OpDir/"execution_payload_bid"
  OpPayloadAttestationDir     = OpDir/"payload_attestation"
  OpProposerSlashingDir       = OpDir/"proposer_slashing"
  OpSyncAggregateDir          = OpDir/"sync_aggregate"
  OpVoluntaryExitDir          = OpDir/"voluntary_exit"
  OpWithdrawalsDir            = OpDir/"withdrawals"

  baseDescription = "EF - Gloas - Operations - "

const testDirs = toHashSet([
  OpAttestationsDir, OpAttSlashingDir, OpBlockHeaderDir,
  OpBlsToExecutionChangeDir, OpConsolidationRequestDir, OpDepositRequestDir,
  OpDepositsDir, OpWithdrawalRequestDir, OpExecutionPayloadDir,
  OpExecutionPayloadBidDir, OpPayloadAttestationDir, OpProposerSlashingDir,
  OpSyncAggregateDir, OpVoluntaryExitDir, OpWithdrawalsDir
])

doAssert toHashSet(
  mapIt(toSeq(walkDir(OpDir, relative = false)), it.path)) == testDirs

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
      parseTest(testDir/"pre.ssz_snappy", SSZ, gloas.BeaconState))
    let done = applyProc(
      preState[], parseTest(testDir/(applyFile & ".ssz_snappy"), SSZ, T))

    if fileExists(testDir/"post.ssz_snappy"):
      let
        postState = newClone(parseTest(
          testDir/"post.ssz_snappy", SSZ, gloas.BeaconState))
        pass = preState[].hash_tree_root() == postState[].hash_tree_root()

      # TODO reportDiff doesn't understand at least one of HashArray or
      # HashList merkle tree caching, so only check if htr's mismatch.
      if not pass:
        reportDiff(preState, postState)
      check:
        done.isOk()
        pass
    else:
      check: done.isErr() # No post state = processing should fail

suite baseDescription & "Attestation " & preset():
  proc applyAttestation(
      preState: var gloas.BeaconState, attestation: electra.Attestation):
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
    runTest[electra.Attestation, typeof applyAttestation](
      OpAttestationsDir, suiteName, "Attestation", "attestation",
      applyAttestation, path)

suite baseDescription & "Attester Slashing " & preset():
  proc applyAttesterSlashing(
      preState: var gloas.BeaconState,
      attesterSlashing: electra.AttesterSlashing): Result[void, cstring] =
    var cache: StateCache
    doAssert (? process_attester_slashing(
      defaultRuntimeConfig, preState, attesterSlashing, {},
      get_state_exit_queue_info(preState), cache))[0] > 0.Gwei
    ok()

  for path in walkTests(OpAttSlashingDir):
    runTest[electra.AttesterSlashing, typeof applyAttesterSlashing](
      OpAttSlashingDir, suiteName, "Attester Slashing", "attester_slashing",
      applyAttesterSlashing, path)

suite baseDescription & "Block Header " & preset():
  proc applyBlockHeader(
      preState: var gloas.BeaconState, blck: gloas.BeaconBlock):
      Result[void, cstring] =
    var cache: StateCache
    process_block_header(preState, blck, {}, cache)

  for path in walkTests(OpBlockHeaderDir):
    runTest[gloas.BeaconBlock, typeof applyBlockHeader](
      OpBlockHeaderDir, suiteName, "Block Header", "block",
      applyBlockHeader, path)

from ../../../beacon_chain/spec/datatypes/capella import
  SignedBLSToExecutionChange

suite baseDescription & "BLS to execution change " & preset():
  proc applyBlsToExecutionChange(
      preState: var gloas.BeaconState,
      signed_address_change: SignedBLSToExecutionChange):
      Result[void, cstring] =
    process_bls_to_execution_change(
      defaultRuntimeConfig, preState, signed_address_change)

  for path in walkTests(OpBlsToExecutionChangeDir):
    runTest[SignedBLSToExecutionChange, typeof applyBlsToExecutionChange](
      OpBlsToExecutionChangeDir, suiteName, "BLS to execution change", "address_change",
      applyBlsToExecutionChange, path)

from ".."/".."/".."/beacon_chain/validator_bucket_sort import
  sortValidatorBuckets

suite baseDescription & "Consolidation Request " & preset():
  proc applyConsolidationRequest(
      preState: var gloas.BeaconState,
      consolidation_request: ConsolidationRequest): Result[void, cstring] =
    var cache: StateCache
    process_consolidation_request(
      defaultRuntimeConfig, preState,
      sortValidatorBuckets(preState.validators.asSeq)[],
      consolidation_request, cache)
    ok()

  for path in walkTests(OpConsolidationRequestDir):
    runTest[ConsolidationRequest, typeof applyConsolidationRequest](
      OpConsolidationRequestDir, suiteName, "Consolidation Request",
      "consolidation_request", applyConsolidationRequest, path)

suite baseDescription & "Deposit " & preset():
  func applyDeposit(
      preState: var gloas.BeaconState, deposit: Deposit):
      Result[void, cstring] =
    process_deposit(
      defaultRuntimeConfig, preState,
      sortValidatorBuckets(preState.validators.asSeq)[], deposit, {})

  for path in walkTests(OpDepositsDir):
    runTest[Deposit, typeof applyDeposit](
      OpDepositsDir, suiteName, "Deposit", "deposit", applyDeposit, path)

suite baseDescription & "Deposit Request " & preset():
  func applyDepositRequest(
      preState: var gloas.BeaconState, depositRequest: DepositRequest):
      Result[void, cstring] =
    var pending = get_pending_validators(defaultRuntimeConfig, preState)
    process_deposit_request(
      defaultRuntimeConfig, preState,
      sortValidatorBuckets(preState.validators.asSeq)[],
      sortValidatorBuckets(preState.builders.asSeq)[], pending, depositRequest, {})

  for path in walkTests(OpDepositRequestDir):
    runTest[DepositRequest, typeof applyDepositRequest](
      OpDepositRequestDir, suiteName, "Deposit Request", "deposit_request",
      applyDepositRequest, path)

suite baseDescription & "Execution Payload " & preset():
  proc makeApplyExecutionPayloadCb(path: string): auto =
    return proc(
        preState: var gloas.BeaconState,
        signed_envelope: SignedExecutionPayloadEnvelope):
        Result[void, cstring] =
      let payloadValid = os_ops.readFile(
          OpExecutionPayloadDir/"pyspec_tests"/path/"execution.yaml"
        ).contains("execution_valid: true")
      var
        cache: StateCache
      let hashedState = (ref gloas.HashedBeaconState)(
        data: preState, root: hash_tree_root(preState))

      func executePayload(_: deneb.ExecutionPayload): bool = payloadValid
      let res = process_execution_payload(
        defaultRuntimeConfig, hashedState[],
        signed_envelope, executePayload, cache)
      preState = hashedState.data
      res

  for path in walkTests(OpExecutionPayloadDir):
    let applyExecutionPayload = makeApplyExecutionPayloadCb(path)
    runTest[SignedExecutionPayloadEnvelope, typeof applyExecutionPayload](
      OpExecutionPayloadDir, suiteName, "Execution Payload", "signed_envelope",
      applyExecutionPayload, path)

suite baseDescription & "Execution Payload Bid " & preset():
  proc applyExecutionPayloadBid(
      preState: var gloas.BeaconState,
      blck: gloas.BeaconBlock): Result[void, cstring] =
    process_execution_payload_bid(
      defaultRuntimeConfig, preState, blck)

  for path in walkTests(OpExecutionPayloadBidDir):
    runTest[gloas.BeaconBlock, typeof applyExecutionPayloadBid](
      OpExecutionPayloadBidDir, suiteName, "Execution Payload Bid",
      "block", applyExecutionPayloadBid, path)

suite baseDescription & "Payload Attestation " & preset():
  proc applyPayloadAttestation(
      preState: var gloas.BeaconState,
      payloadAttestation: PayloadAttestation): Result[void, cstring] =
    process_payload_attestation(preState, payloadAttestation)

  for path in walkTests(OpPayloadAttestationDir):
    runTest[PayloadAttestation, typeof applyPayloadAttestation](
      OpPayloadAttestationDir, suiteName, "Payload Attestation",
      "payload_attestation", applyPayloadAttestation, path)

suite baseDescription & "Withdrawal Request " & preset():
  func applyWithdrawalRequest(
      preState: var gloas.BeaconState, withdrawalRequest: WithdrawalRequest):
      Result[void, cstring] =
    var cache: StateCache
    process_withdrawal_request(
      defaultRuntimeConfig, preState,
      sortValidatorBuckets(preState.validators.asSeq)[], withdrawalRequest,
      cache)
    ok()

  for path in walkTests(OpWithdrawalRequestDir):
    runTest[WithdrawalRequest, typeof applyWithdrawalRequest](
      OpWithdrawalRequestDir, suiteName, "Withdrawal Request",
      "withdrawal_request", applyWithdrawalRequest, path)

suite baseDescription & "Proposer Slashing " & preset():
  proc applyProposerSlashing(
      preState: var gloas.BeaconState, proposerSlashing: ProposerSlashing):
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
      preState: var gloas.BeaconState, syncAggregate: SyncAggregate):
      Result[void, cstring] =
    var cache: StateCache
    discard ? process_sync_aggregate(
      preState, syncAggregate, get_total_active_balance(preState, cache),
      {}, cache)
    ok()

  for path in walkTests(OpSyncAggregateDir):
    runTest[SyncAggregate, typeof applySyncAggregate](
      OpSyncAggregateDir, suiteName, "Sync Aggregate", "sync_aggregate",
      applySyncAggregate, path)

suite baseDescription & "Voluntary Exit " & preset():
  proc applyVoluntaryExit(
      preState: var gloas.BeaconState, voluntaryExit: SignedVoluntaryExit):
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
  for path in walkTests(OpWithdrawalsDir):
    # See: https://github.com/status-im/nimbus-eth2/pull/7926#discussion_r2776852494
    if path in ["invalid_validator_index_pending_partial", 
                "invalid_builder_index_sweep", 
                "invalid_validator_index_sweep",
                "invalid_builder_index_pending"]:
      continue
    let prefix =
      if fileExists(OpWithdrawalsDir / "pyspec_tests" / path / "post.ssz_snappy"):
        "[Valid]   "
      else:
        "[Invalid] "
    
    test prefix & baseDescription & "Withdrawals - " & path:
      let
        testDir = OpWithdrawalsDir / "pyspec_tests" / path
        preState = newClone(
          parseTest(testDir/"pre.ssz_snappy", SSZ, gloas.BeaconState))
        done = process_withdrawals(preState[])

      if fileExists(testDir/"post.ssz_snappy"):
        let 
          postState = newClone(parseTest(
            testDir/"post.ssz_snappy", SSZ, gloas.BeaconState))
          pass = preState[].hash_tree_root() == postState[].hash_tree_root()
        if not pass:
          reportDiff(preState, postState)
        check:
          done.isOk()
          pass
      else:
        check: done.isErr()
