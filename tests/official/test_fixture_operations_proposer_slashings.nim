# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, state_transition_block, validator],
  ../../beacon_chain/[ssz, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

const OpProposerSlashingDir = SszTestsDir/const_preset/"phase0"/"operations"/"proposer_slashing"/"pyspec_tests"

template runTest(identifier: untyped) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  const testDir = OpProposerSlashingDir / astToStr(identifier)

  proc `testImpl_proposer_slashing _ identifier`() =

    var flags: UpdateFlags
    var prefix: string
    if not existsFile(testDir/"meta.yaml"):
      flags.incl skipValidation
    if existsFile(testDir/"post.ssz"):
      prefix = "[Valid]   "
    else:
      prefix = "[Invalid] "

    test prefix & astToStr(identifier):
      var stateRef, postRef: ref BeaconState
      var proposerSlashing: ref ProposerSlashing
      new proposerSlashing
      new stateRef

      proposerSlashing[] = parseTest(testDir/"proposer_slashing.ssz", SSZ, ProposerSlashing)
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      if existsFile(testDir/"post.ssz"):
        new postRef
        postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      var cache = get_empty_per_epoch_cache()

      if postRef.isNil:
        let done = process_proposer_slashing(stateRef[], proposerSlashing[], flags, cache)
        doAssert done == false, "We didn't expect this invalid proposer slashing to be processed."
      else:
        let done = process_proposer_slashing(stateRef[], proposerSlashing[], flags, cache)
        doAssert done, "Valid proposer slashing not processed"
        check: stateRef.hash_tree_root() == postRef.hash_tree_root()
        reportDiff(stateRef, postRef)

  `testImpl_proposer_slashing _ identifier`()

suite "Official - Operations - Proposer slashing " & preset():
  runTest(success)
  runTest(invalid_sig_1)
  runTest(invalid_sig_2)
  runTest(invalid_sig_1_and_2)
  runTest(invalid_proposer_index)
  runTest(epochs_are_different)
  runTest(headers_are_same)
  runTest(proposer_is_not_activated)
  runTest(proposer_is_slashed)
  runTest(proposer_is_withdrawn)
