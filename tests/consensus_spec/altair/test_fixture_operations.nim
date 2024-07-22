# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
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
  ../../../beacon_chain/spec/[beaconstate, state_transition_block],
  ../../../beacon_chain/spec/datatypes/altair,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops,
  ../../helpers/debug_state

from std/sequtils import mapIt, toSeq

const
  OpDir                 = SszTestsDir/const_preset/"altair"/"operations"
  OpAttestationsDir     = OpDir/"attestation"
  OpAttSlashingDir      = OpDir/"attester_slashing"
  OpBlockHeaderDir      = OpDir/"block_header"
  OpDepositsDir         = OpDir/"deposit"
  OpProposerSlashingDir = OpDir/"proposer_slashing"
  OpSyncAggregateDir    = OpDir/"sync_aggregate"
  OpVoluntaryExitDir    = OpDir/"voluntary_exit"

  baseDescription = "EF - Altair - Operations - "

doAssert toHashSet(mapIt(toSeq(walkDir(OpDir, relative = false)), it.path)) ==
  toHashSet([OpAttestationsDir, OpAttSlashingDir, OpBlockHeaderDir,
             OpDepositsDir, OpProposerSlashingDir, OpSyncAggregateDir,
             OpVoluntaryExitDir])

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
      parseTest(testDir/"pre.ssz_snappy", SSZ, altair.BeaconState))
    let done = applyProc(
      preState[], parseTest(testDir/(applyFile & ".ssz_snappy"), SSZ, T))

    if fileExists(testDir/"post.ssz_snappy"):
      let postState =
        newClone(parseTest(testDir/"post.ssz_snappy", SSZ, altair.BeaconState))

      check:
        done.isOk()
        preState[].hash_tree_root() == postState[].hash_tree_root()
      reportDiff(preState, postState)
    else:
      check: done.isErr() # No post state = processing should fail

suite baseDescription & "Attestation " & preset():
  proc applyAttestation(
      preState: var altair.BeaconState, attestation: phase0.Attestation):
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
      preState: var altair.BeaconState,
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
      preState: var altair.BeaconState, blck: altair.BeaconBlock):
      Result[void, cstring] =
    var cache: StateCache
    process_block_header(preState, blck, {}, cache)

  for path in walkTests(OpBlockHeaderDir):
    runTest[altair.BeaconBlock, typeof applyBlockHeader](
      OpBlockHeaderDir, suiteName, "Block Header", "block", applyBlockHeader, path)

from ".."/".."/".."/beacon_chain/bloomfilter import constructBloomFilter

suite baseDescription & "Deposit " & preset():
  proc applyDeposit(
      preState: var altair.BeaconState, deposit: Deposit):
      Result[void, cstring] =
    process_deposit(
      defaultRuntimeConfig, preState,
      constructBloomFilter(preState.validators.asSeq)[], deposit, {})

  for path in walkTests(OpDepositsDir):
    runTest[Deposit, typeof applyDeposit](
      OpDepositsDir, suiteName, "Deposit", "deposit", applyDeposit, path)

suite baseDescription & "Proposer Slashing " & preset():
  proc applyProposerSlashing(
      preState: var altair.BeaconState, proposerSlashing: ProposerSlashing):
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
      preState: var altair.BeaconState, syncAggregate: SyncAggregate):
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
      preState: var altair.BeaconState, voluntaryExit: SignedVoluntaryExit):
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
