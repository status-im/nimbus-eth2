# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest, strutils,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, beaconstate, validator],
  ../../beacon_chain/[ssz, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state,
  ../mocking/mock_blocks

const OpAttSlashingDir = SszTestsDir/const_preset/"phase0"/"operations"/"attester_slashing"/"pyspec_tests"

template runTest(identifier: untyped) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  const testDir = OpAttSlashingDir / astToStr(identifier)

  proc `testImpl _ operations_attestater_slashing _ identifier`() =

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
      var attesterSlashingRef: ref AttesterSlashing
      new attesterSlashingRef
      new stateRef

      var cache = get_empty_per_epoch_cache()

      attesterSlashingRef[] = parseTest(testDir/"attester_slashing.ssz", SSZ, AttestaterSlashing)
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      if existsFile(testDir/"post.ssz"):
        new postRef
        postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      if postRef.isNil:
        let done = process_attester_slashing(stateRef[], attesterSlashingRef[], flags, cache)
        doAssert done == false, "We didn't expect this invalid attester slashing to be processed."
      else:
        let done = process_attester_slashing(stateRef[], attesterSlashingRef[], flags, cache)
        doAssert done, "Valid attestater slashing not processed"
        check: stateRef.hash_tree_root() == postRef.hash_tree_root()
        reportDiff(stateRef, postRef)

  `testImpl _ operations_attestater_slashing _ identifier`()

suite "Official - Operations - Attester slashing " & preset():
  runTest(success_double)
  runTest(success_surround)
  runTest(success_already_exited_recent)
  runTest(success_already_exited_long_ago)
  runTest(invalid_sig_1)
  runTest(invalid_sig_2)
  runTest(invalid_sig_1_and_2)
  runTest(same_data)
  runTest(no_double_or_surround)
  runTest(participants_already_slashed)
  runTest(custody_bit_0_and_1_intersect)
  runTest(att1_bad_extra_index)
  runTest(att1_bad_replaced_index)
  runTest(att2_bad_extra_index)
  runTest(att2_bad_replaced_index)
  runTest(unsorted_att_1_bit0)
  runTest(unsorted_att_2_bit_0)

