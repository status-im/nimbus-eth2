# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[sequtils, sets, strutils],
  # Utilities
  chronicles,
  unittest2,
  stew/results,
  # Beacon chain internals
  ../../../beacon_chain/spec/[beaconstate, state_transition_block],
  ../../../beacon_chain/spec/datatypes/deneb,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops,
  ../../helpers/debug_state

const
  OpDir                     = SszTestsDir/const_preset/"deneb"/"operations"
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

  baseDescription = "EF - Deneb - Operations - "

doAssert toHashSet(mapIt(toSeq(walkDir(OpDir, relative = false)), it.path)) ==
  toHashSet([
    OpAttestationsDir, OpAttSlashingDir, OpBlockHeaderDir,
    OpBlsToExecutionChangeDir, OpDepositsDir, OpExecutionPayloadDir,
    OpProposerSlashingDir, OpSyncAggregateDir, OpVoluntaryExitDir,
    OpWithdrawalsDir])

proc runTest[T, U](
    testSuiteDir: string, testSuiteName: string, applyFile: string,
    applyProc: U, identifier: string) =
  let testDir = testSuiteDir / "pyspec_tests" / identifier

  proc testImpl() =
    let prefix =
      if fileExists(testDir/"post.ssz_snappy"):
        "[Valid]   "
      else:
        "[Invalid] "

    test prefix & baseDescription & testSuiteName & " - " & identifier:
      let preState = newClone(
        parseTest(testDir/"pre.ssz_snappy", SSZ, deneb.BeaconState))
      let done = applyProc(
        preState[], parseTest(testDir/(applyFile & ".ssz_snappy"), SSZ, T))

      if fileExists(testDir/"post.ssz_snappy"):
        let postState =
          newClone(parseTest(
            testDir/"post.ssz_snappy", SSZ, deneb.BeaconState))

        reportDiff(preState, postState)
        check:
          done.isOk()
          preState[].hash_tree_root() == postState[].hash_tree_root()
      else:
        check: done.isErr() # No post state = processing should fail

  testImpl()

suite baseDescription & "Attestation " & preset():
  proc applyAttestation(
      preState: var deneb.BeaconState, attestation: Attestation):
      Result[void, cstring] =
    var cache = StateCache()
    let
      total_active_balance = get_total_active_balance(preState, cache)
      base_reward_per_increment =
        get_base_reward_per_increment(total_active_balance)

    process_attestation(
      preState, attestation, {}, base_reward_per_increment, cache)

  for path in walkTests(OpAttestationsDir):
    runTest[Attestation, typeof applyAttestation](
      OpAttestationsDir, "Attestation", "attestation", applyAttestation, path)

suite baseDescription & "Attester Slashing " & preset():
  proc applyAttesterSlashing(
      preState: var deneb.BeaconState, attesterSlashing: AttesterSlashing):
      Result[void, cstring] =
    var cache = StateCache()
    process_attester_slashing(
      defaultRuntimeConfig, preState, attesterSlashing, {}, cache)

  for path in walkTests(OpAttSlashingDir):
    runTest[AttesterSlashing, typeof applyAttesterSlashing](
      OpAttSlashingDir, "Attester Slashing", "attester_slashing",
      applyAttesterSlashing, path)

suite baseDescription & "Block Header " & preset():
  func applyBlockHeader(
      preState: var deneb.BeaconState, blck: deneb.BeaconBlock):
      Result[void, cstring] =
    var cache = StateCache()
    process_block_header(preState, blck, {}, cache)

  for path in walkTests(OpBlockHeaderDir):
    runTest[deneb.BeaconBlock, typeof applyBlockHeader](
      OpBlockHeaderDir, "Block Header", "block", applyBlockHeader, path)

from ../../../beacon_chain/spec/datatypes/capella import
  SignedBLSToExecutionChange

suite baseDescription & "BLS to execution change " & preset():
  proc applyBlsToExecutionChange(
      preState: var deneb.BeaconState,
      signed_address_change: SignedBLSToExecutionChange):
      Result[void, cstring] =
    process_bls_to_execution_change(
      defaultRuntimeConfig, preState, signed_address_change)

  for path in walkTests(OpBlsToExecutionChangeDir):
    runTest[SignedBLSToExecutionChange, typeof applyBlsToExecutionChange](
      OpBlsToExecutionChangeDir, "BLS to execution change", "address_change",
      applyBlsToExecutionChange, path)

suite baseDescription & "Deposit " & preset():
  proc applyDeposit(
      preState: var deneb.BeaconState, deposit: Deposit):
      Result[void, cstring] =
    process_deposit(defaultRuntimeConfig, preState, deposit, {})

  for path in walkTests(OpDepositsDir):
    runTest[Deposit, typeof applyDeposit](
      OpDepositsDir, "Deposit", "deposit", applyDeposit, path)

suite baseDescription & "Execution Payload " & preset():
  for path in walkTests(OpExecutionPayloadDir):
    proc applyExecutionPayload(
        preState: var deneb.BeaconState,
        executionPayload: deneb.ExecutionPayload):
        Result[void, cstring] =
      let payloadValid =
        os_ops.readFile(OpExecutionPayloadDir/"pyspec_tests"/path/"execution.yaml").
          contains("execution_valid: true")
      func executePayload(_: deneb.ExecutionPayload): bool = payloadValid
      process_execution_payload(
            preState, executionPayload, executePayload)

    runTest[deneb.ExecutionPayload, typeof applyExecutionPayload](
      OpExecutionPayloadDir, "Execution Payload", "execution_payload",
      applyExecutionPayload, path)

suite baseDescription & "Proposer Slashing " & preset():
  proc applyProposerSlashing(
      preState: var deneb.BeaconState, proposerSlashing: ProposerSlashing):
      Result[void, cstring] =
    var cache = StateCache()
    process_proposer_slashing(
      defaultRuntimeConfig, preState, proposerSlashing, {}, cache)

  for path in walkTests(OpProposerSlashingDir):
    runTest[ProposerSlashing, typeof applyProposerSlashing](
      OpProposerSlashingDir, "Proposer Slashing", "proposer_slashing",
      applyProposerSlashing, path)

suite baseDescription & "Sync Aggregate " & preset():
  proc applySyncAggregate(
      preState: var deneb.BeaconState, syncAggregate: SyncAggregate):
      Result[void, cstring] =
    var cache = StateCache()
    process_sync_aggregate(
      preState, syncAggregate, get_total_active_balance(preState, cache), cache)

  for path in walkTests(OpSyncAggregateDir):
    runTest[SyncAggregate, typeof applySyncAggregate](
      OpSyncAggregateDir, "Sync Aggregate", "sync_aggregate",
      applySyncAggregate, path)

suite baseDescription & "Voluntary Exit " & preset():
  proc applyVoluntaryExit(
      preState: var deneb.BeaconState, voluntaryExit: SignedVoluntaryExit):
      Result[void, cstring] =
    var cache = StateCache()
    process_voluntary_exit(
      defaultRuntimeConfig, preState, voluntaryExit, {}, cache)

  for path in walkTests(OpVoluntaryExitDir):
    runTest[SignedVoluntaryExit, typeof applyVoluntaryExit](
      OpVoluntaryExitDir, "Voluntary Exit", "voluntary_exit",
      applyVoluntaryExit, path)

suite baseDescription & "Withdrawals " & preset():
  proc applyWithdrawals(
      preState: var deneb.BeaconState,
      executionPayload: deneb.ExecutionPayload): Result[void, cstring] =
    process_withdrawals(preState, executionPayload)

  for path in walkTests(OpWithdrawalsDir):
    runTest[deneb.ExecutionPayload, typeof applyWithdrawals](
      OpWithdrawalsDir, "Withdrawals", "execution_payload",
      applyWithdrawals, path)
