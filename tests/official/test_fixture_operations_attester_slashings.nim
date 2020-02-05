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
  ../../beacon_chain/spec/[datatypes, state_transition_block, validator],
  ../../beacon_chain/[extras, ssz],
  # Test utilities
  ../testutil,
  ./fixtures_utils,
  ../helpers/debug_state

const OpAttSlashingDir = SszTestsDir/const_preset/"phase0"/"operations"/"attester_slashing"/"pyspec_tests"

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  let testDir = OpAttSlashingDir / identifier

  proc `testImpl _ operations_attester_slashing _ identifier`() =

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
      var attesterSlashingRef: ref AttesterSlashing
      new attesterSlashingRef
      new stateRef

      var cache = get_empty_per_epoch_cache()

      attesterSlashingRef[] = parseTest(testDir/"attester_slashing.ssz", SSZ, AttesterSlashing)
      stateRef[] = parseTest(testDir/"pre.ssz", SSZ, BeaconState)

      if existsFile(testDir/"post.ssz"):
        new postRef
        postRef[] = parseTest(testDir/"post.ssz", SSZ, BeaconState)

      if postRef.isNil:
        let done = process_attester_slashing(stateRef[], attesterSlashingRef[],
          flags, cache)
        doAssert done == false, "We didn't expect this invalid attester slashing to be processed."
      else:
        let done = process_attester_slashing(stateRef[], attesterSlashingRef[],
          flags, cache)
        doAssert done, "Valid attestater slashing not processed"
        check: stateRef.hash_tree_root() == postRef.hash_tree_root()
        reportDiff(stateRef, postRef)

  `testImpl _ operations_attester_slashing _ identifier`()

suite "Official - Operations - Attester slashing " & preset():
  # TODO these are both valid and check BLS signatures, which isn't working
  # since 0.10.x introduces new BLS signing/verifying interface with domain
  # in particular handled differently through compute_signing_root() rather
  # than through the bls_verify(...) call directly. This did not become the
  # visible issue it now is because another bug had been masking it wherein
  # crypto.nim's bls_verify(...) call had been creating false positives, in
  # which cases signature checks had been incorrectly passing.
  const expected_failures =
    ["success_already_exited_recent", "success_already_exited_long_ago"]
  for kind, path in walkDir(OpAttSlashingDir, true):
    if path in expected_failures:
      echo "Skipping test: ", path
      continue
    runTest(path)
