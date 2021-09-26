# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/os, std/strutils,
  # Utilities
  stew/results,
  # Beacon chain internals
  ../../../beacon_chain/spec/state_transition_block,
  ../../../beacon_chain/spec/datatypes/merge,
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../../helpers/debug_state

const OpExecutionPayloadDir = SszTestsDir/const_preset/"merge"/"operations"/"execution_payload"/"pyspec_tests"

proc runTest(identifier: string) =
  # We wrap the tests in a proc to avoid running out of globals
  # in the future: Nim supports up to 3500 globals
  # but unittest with the macro/templates put everything as globals
  # https://github.com/nim-lang/Nim/issues/12084#issue-486866402

  let testDir = OpExecutionPayloadDir / identifier

  proc `testImpl _ voluntary_exit _ identifier`() =

    let
      prefix =
        if existsFile(testDir/"post.ssz_snappy"):
          "[Valid]   "
        else:
          "[Invalid] "
      payloadValid = readFile(
        testDir/"execution.yaml").contains("execution_valid: true")

    func executePayload(_: ExecutionPayload): bool = payloadValid

    test prefix & identifier:
      let
        executionPayload = parseTest(
          testDir/"execution_payload.ssz_snappy", SSZ, ExecutionPayload)
      var preState = newClone(
        parseTest(testDir/"pre.ssz_snappy", SSZ, merge.BeaconState))

      if existsFile(testDir/"post.ssz_snappy"):
        let
          postState = newClone(
            parseTest(testDir/"post.ssz_snappy", SSZ, merge.BeaconState))
          done = process_execution_payload(
            preState[], executionPayload, executePayload).isOk
        doAssert done, "Valid execution payload not processed"
        check: preState[].hash_tree_root() == postState[].hash_tree_root()
        reportDiff(preState, postState)
      else:
        let done = process_execution_payload(
          preState[], executionPayload, executePayload).isOk
        doAssert done == false, "We didn't expect this invalid execution payload to be processed."

  `testImpl _ voluntary_exit _ identifier`()

suite "Ethereum Foundation - Merge - Operations - Execution Payload " & preset():
  for kind, path in walkDir(
      OpExecutionPayloadDir, relative = true, checkDir = true):
    runTest(path)
