# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

# This implements the pre-release proposal of the libp2p based light client sync
# protocol. See https://github.com/ethereum/consensus-specs/pull/2802

import
  # Standard library
  std/[json, os, streams],
  # Status libraries
  stew/bitops2,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../../beacon_chain/spec/light_client_sync,
  ../../../beacon_chain/spec/datatypes/altair,
  # Test utilities
  ../../testutil,
  ../fixtures_utils

const TestsDir =
  SszTestsDir/const_preset/"altair"/"sync_protocol"/"light_client_sync"/"pyspec_tests"

type
  TestMeta = object
    genesis_validators_root: string
    trusted_block_root: string

  TestStepKind {.pure.} = enum
    ForceUpdate
    ProcessUpdate

  TestStep = object
    case kind: TestStepKind
    of TestStepKind.ForceUpdate:
      discard
    of TestStepKind.ProcessUpdate:
      update: altair.LightClientUpdate
    current_slot: Slot

proc loadSteps(path: string): seq[TestStep] =
  let stepsYAML = readFile(path/"steps.yaml")
  let steps = yaml.loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    if step.hasKey"force_update":
      let s = step["force_update"]
      result.add TestStep(kind: TestStepKind.ForceUpdate,
                          current_slot: s["current_slot"].getInt().Slot)
    elif step.hasKey"process_update":
      let
        s = step["process_update"]
        filename = s["update"].getStr()
        update = parseTest(path/filename & ".ssz_snappy", SSZ,
                           altair.LightClientUpdate)
      result.add TestStep(kind: TestStepKind.ProcessUpdate,
                          update: update,
                          current_slot: s["current_slot"].getInt().Slot)
    else:
      doAssert false, "Unreachable: " & $step

proc runTest(identifier: string) =
  let testDir = TestsDir / identifier

  proc `testImpl _ sync_protocol_light_client_sync _ identifier`() =
    test identifier:
      let
        meta = block:
          var s = openFileStream(testDir/"meta.yaml")
          defer: close(s)
          var res: TestMeta
          yaml.load(s, res)
          res
        genesis_validators_root =
          Eth2Digest.fromHex(meta.genesis_validators_root)
        trusted_block_root =
          Eth2Digest.fromHex(meta.trusted_block_root)

        bootstrap = parseTest(testDir/"bootstrap.ssz_snappy", SSZ,
                              altair.LightClientBootstrap)
        steps = loadSteps(testDir)

        expected_finalized_header =
          parseTest(testDir/"expected_finalized_header.ssz_snappy", SSZ,
                    BeaconBlockHeader)
        expected_optimistic_header =
          parseTest(testDir/"expected_optimistic_header.ssz_snappy", SSZ,
                    BeaconBlockHeader)

      var cfg = defaultRuntimeConfig
      cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH

      var store =
        initialize_light_client_store(trusted_block_root, bootstrap).get

      for step in steps:
        case step.kind
        of TestStepKind.ForceUpdate:
          try_light_client_store_force_update(
            store, step.current_slot)
        of TestStepKind.ProcessUpdate:
          let res = process_light_client_update(
            store, step.update, step.current_slot,
            cfg, genesis_validators_root)
          check res.isOk

      check:
        store.finalized_header == expected_finalized_header
        store.optimistic_header == expected_optimistic_header

  `testImpl _ sync_protocol_light_client_sync _ identifier`()

suite "EF - Altair - Sync protocol - Light client" & preset():
  try:
    for kind, path in walkDir(TestsDir, relative = true, checkDir = true):
      runTest(path)
  except OSError:
    # These tests are for the pre-release proposal of the libp2p based light
    # client sync protocol. Corresponding test vectors need manual integration.
    # https://github.com/ethereum/consensus-specs/pull/2802
    #
    # To locally integrate the test vectors, clone the pre-release spec repo
    # at latest commit of https://github.com/ethereum/consensus-specs/pull/2802
    # and place it next to the `nimbus-eth2` repo, so that `nimbus-eth2` and
    # `consensus-specs` are in the same directory.
    #
    # To generate the additional test vectors, from `consensus-specs`:
    # $ rm -rf ../consensus-spec-tests && \
    #   doctoc specs && make lint && make gen_sync_protocol
    #
    # To integrate the additional test vectors into `nimbus-eth2`, first run
    # `make test` from `nimbus-eth2` to ensure that the regular test vectors
    # have been downloaded and extracted, then proceed from `nimbus-eth2` with:
    # $ rsync -r ../consensus-spec-tests/tests/ \
    #   ../nimbus-eth2/vendor/nim-eth2-scenarios/tests-v1.1.10/
    test "All tests":
      skip()
