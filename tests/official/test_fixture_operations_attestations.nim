# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, unittest,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, beaconstate, validator],
  ../../beacon_chain/[ssz, extras],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

const OperationsAttestationsDir = SszTestsDir/const_preset/"phase0"/"operations"/"attestation"/"pyspec_tests"

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  let testDir = OperationsAttestationsDir / identifier

  proc `testImpl _ operations_attestations _ identifier`() =

    var flags: UpdateFlags
    var prefix: string
    if not existsFile(testDir/"meta.yaml"):
      flags.incl skipValidation
    if existsFile(testDir/"post.ssz"):
      prefix = "[Valid]   "
    else:
      prefix = "[Invalid] "

    timedTest prefix & identifier:
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
  for kind, path in walkDir(OperationsAttestationsDir, true):
    runTest(path)
