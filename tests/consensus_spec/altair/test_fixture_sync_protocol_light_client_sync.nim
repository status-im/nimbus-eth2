# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

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
    ProcessSlot
    ProcessUpdate
    ProcessOptimisticUpdate

  TestStep = object
    case kind: TestStepKind
    of TestStepKind.ProcessSlot:
      discard
    of TestStepKind.ProcessUpdate:
      update: altair.LightClientUpdate
    of TestStepKind.ProcessOptimisticUpdate:
      optimistic_update: OptimisticLightClientUpdate
    current_slot: Slot

proc loadSteps(path: string): seq[TestStep] =
  let stepsYAML = readFile(path/"steps.yaml")
  let steps = yaml.loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    if step.hasKey"process_slot":
      let s = step["process_slot"]
      result.add TestStep(kind: TestStepKind.ProcessSlot,
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
    elif step.hasKey"process_optimistic_update":
      let
        s = step["process_optimistic_update"]
        filename = s["optimistic_update"].getStr()
        optimistic_update = parseTest(path/filename & ".ssz_snappy", SSZ,
                                      OptimisticLightClientUpdate)
      result.add TestStep(kind: TestStepKind.ProcessOptimisticUpdate,
                          optimistic_update: optimistic_update,
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
        of TestStepKind.ProcessSlot:
          process_slot_for_light_client_store(
            store, step.current_slot)
        of TestStepKind.ProcessUpdate:
          let res = process_light_client_update(
            store, step.update, step.current_slot,
            cfg, genesis_validators_root)
          check res.isOk
        of TestStepKind.ProcessOptimisticUpdate:
          let res = process_optimistic_light_client_update(
            store, step.optimistic_update, step.current_slot,
            cfg, genesis_validators_root)
          check res.isOk

      check:
        store.finalized_header == expected_finalized_header
        store.optimistic_header == expected_optimistic_header

  `testImpl _ sync_protocol_light_client_sync _ identifier`()

suite "EF - Altair - Sync protocol - Light client" & preset():
  for kind, path in walkDir(TestsDir, relative = true, checkDir = true):
    runTest(path)
