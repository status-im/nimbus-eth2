# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[sequtils, sets],
  # Utilities
  chronicles,
  unittest2,
  stew/results,
  # Beacon chain internals
  ../../../beacon_chain/spec/[beaconstate, state_transition_block],
  ../../../beacon_chain/spec/datatypes/phase0,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops,
  ../../helpers/debug_state

const
  OpDir                 = SszTestsDir/const_preset/"phase0"/"operations"
  OpAttestationsDir     = OpDir/"attestation"
  OpAttSlashingDir      = OpDir/"attester_slashing"
  OpBlockHeaderDir      = OpDir/"block_header"
  OpDepositsDir         = OpDir/"deposit"
  OpProposerSlashingDir = OpDir/"proposer_slashing"
  OpVoluntaryExitDir    = OpDir/"voluntary_exit"

  baseDescription = "EF - Phase 0 - Operations - "

doAssert toHashSet(mapIt(toSeq(walkDir(OpDir, relative = false)), it.path)) ==
  toHashSet([OpAttestationsDir, OpAttSlashingDir, OpBlockHeaderDir,
             OpDepositsDir, OpProposerSlashingDir, OpVoluntaryExitDir])

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
        parseTest(testDir/"pre.ssz_snappy", SSZ, phase0.BeaconState))
      let done = applyProc(
        preState[], parseTest(testDir/(applyFile & ".ssz_snappy"), SSZ, T))

      if fileExists(testDir/"post.ssz_snappy"):
        let postState =
          newClone(parseTest(testDir/"post.ssz_snappy", SSZ, phase0.BeaconState))

        check:
          done.isOk()
          preState[].hash_tree_root() == postState[].hash_tree_root()
        reportDiff(preState, postState)
      else:
        check: done.isErr() # No post state = processing should fail

  testImpl()

suite baseDescription & "Attestation " & preset():
  proc applyAttestation(
      preState: var phase0.BeaconState, attestation: Attestation):
      Result[void, cstring] =
    var cache = StateCache()
    process_attestation(preState, attestation, {}, 0.Gwei, cache)

  for path in walkTests(OpAttestationsDir):
    runTest[Attestation, typeof applyAttestation](
      OpAttestationsDir, "Attestation", "attestation", applyAttestation, path)

suite baseDescription & "Attester Slashing " & preset():
  proc applyAttesterSlashing(
      preState: var phase0.BeaconState, attesterSlashing: AttesterSlashing):
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
      preState: var phase0.BeaconState, blck: phase0.BeaconBlock):
      Result[void, cstring] =
    var cache = StateCache()
    process_block_header(preState, blck, {}, cache)

  for path in walkTests(OpBlockHeaderDir):
    runTest[phase0.BeaconBlock, typeof applyBlockHeader](
      OpBlockHeaderDir, "Block Header", "block", applyBlockHeader, path)

suite baseDescription & "Deposit " & preset():
  proc applyDeposit(
      preState: var phase0.BeaconState, deposit: Deposit):
      Result[void, cstring] =
    process_deposit(defaultRuntimeConfig, preState, deposit, {})

  for path in walkTests(OpDepositsDir):
    runTest[Deposit, typeof applyDeposit](
      OpDepositsDir, "Deposit", "deposit", applyDeposit, path)

suite baseDescription & "Proposer Slashing " & preset():
  proc applyProposerSlashing(
      preState: var phase0.BeaconState, proposerSlashing: ProposerSlashing):
      Result[void, cstring] =
    var cache = StateCache()
    process_proposer_slashing(
      defaultRuntimeConfig, preState, proposerSlashing, {}, cache)

  for path in walkTests(OpProposerSlashingDir):
    runTest[ProposerSlashing, typeof applyProposerSlashing](
      OpProposerSlashingDir, "Proposer Slashing", "proposer_slashing",
      applyProposerSlashing, path)

suite baseDescription & "Voluntary Exit " & preset():
  proc applyVoluntaryExit(
      preState: var phase0.BeaconState, voluntaryExit: SignedVoluntaryExit):
      Result[void, cstring] =
    var cache = StateCache()
    process_voluntary_exit(
      defaultRuntimeConfig, preState, voluntaryExit, {}, cache)

  for path in walkTests(OpVoluntaryExitDir):
    runTest[SignedVoluntaryExit, typeof applyVoluntaryExit](
      OpVoluntaryExitDir, "Voluntary Exit", "voluntary_exit",
      applyVoluntaryExit, path)
