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
  ../../beacon_chain/spec/[datatypes, beaconstate, validator],
  ../../beacon_chain/[ssz, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state,
  ../mocking/mock_blocks

const OperationsAttestationsDir = SszTestsDir/const_preset/"phase0"/"operations"/"attestation"/"pyspec_tests"

template runTest(testName: string, identifier: untyped) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  const testDir = OperationsAttestationsDir / astToStr(identifier)

  proc `testImpl _ operations_attestations _ identifier`() =

    var flags: UpdateFlags
    var prefix: string
    if not existsFile(testDir/"meta.yaml"):
      flags.incl skipValidation
    if existsFile(testDir/"post.ssz"):
      prefix = "[Valid]   "
    else:
      prefix = "[Invalid] "

    test prefix & testName & " (" & astToStr(identifier) & ")":
      var stateRef, postRef: ref BeaconState
      var attestationRef: ref Attestation
      new attestationRef
      new stateRef

      var cache = get_empty_per_epoch_cache()

      attestationRef[] = parseTest(testDir/"attestation.ssz", SSZ, Attestation)
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      if existsFile(testDir/"post.ssz"):
        new postRef
        postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      if postRef.isNil:
        let done = process_attestation(stateRef[], attestationRef[], flags, cache)
        doAssert done == false, "We didn't expect this invalid attestation to be processed."
      else:
        let done = process_attestation(stateRef[], attestationRef[], flags, cache)
        doAssert done, "Valid attestation not processed"
        check: stateRef.hash_tree_root() == postRef.hash_tree_root()
        reportDiff(stateRef, postRef)

  `testImpl _ operations_attestations _ identifier`()

suite "Official - Operations - Attestations " & preset():
  runTest("success", success)
  runTest("success previous epoch", success_previous_epoch)
  when const_preset == "minimal":
    runTest("success since max epochs per crosslink", success_since_max_epochs_per_crosslink)
    runTest("wrong end epoch with max epochs per crosslink", wrong_end_epoch_with_max_epochs_per_crosslink)
  runTest("invalid attestation signature", invalid_attestation_signature)
  runTest("before inclusion delay", before_inclusion_delay)
  runTest("after_epoch_slots", after_epoch_slots)
  runTest("old source epoch", old_source_epoch)
  runTest("wrong shard", wrong_shard)
  runTest("invalid shard", invalid_shard)
  runTest("old target epoch", old_target_epoch)
  runTest("future target epoch", future_target_epoch)
  runTest("new source epoch", new_source_epoch)
  runTest("source root is target root", source_root_is_target_root)
  runTest("invalid current source root", invalid_current_source_root)
  runTest("bad source root", bad_source_root)
  runTest("non-zero crosslink data root", non_zero_crosslink_data_root)
  runTest("bad parent crosslink", bad_parent_crosslink)
  runTest("bad crosslink start epoch", bad_crosslink_start_epoch)
  runTest("bad crosslink end epoch", bad_crosslink_end_epoch)
  runTest("inconsistent bits", inconsistent_bits)
  runTest("non-empty custody bits", non_empty_custody_bits)
  runTest("empty aggregation bits", empty_aggregation_bits)
  runTest("too many aggregation bits", too_many_aggregation_bits)
  runTest("too few aggregation bits", too_few_aggregation_bits)
  runTest("too many custody bits", too_many_custody_bits)
  runTest("too few custody bits", too_few_custody_bits)
