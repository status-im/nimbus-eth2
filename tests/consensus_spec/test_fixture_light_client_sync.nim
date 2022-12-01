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
  # Third-party
  yaml,
  # Beacon chain internals
  ../../../beacon_chain/spec/light_client_sync,
  ../../../beacon_chain/spec/datatypes/altair,
  # Test utilities
  ../testutil,
  ./fixtures_utils

type
  TestMeta = object
    genesis_validators_root: string
    trusted_block_root: string

  TestChecks = object
    finalized_slot: Slot
    finalized_root: Eth2Digest
    optimistic_slot: Slot
    optimistic_root: Eth2Digest

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
    checks: TestChecks

proc loadSteps(path: string): seq[TestStep] =
  let stepsYAML = readFile(path/"steps.yaml")
  let steps = yaml.loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    func getChecks(c: JsonNode): TestChecks =
      TestChecks(
        finalized_slot:
          c["finalized_header"]["slot"].getInt().Slot,
        finalized_root:
          Eth2Digest.fromHex(c["finalized_header"]["beacon_root"].getStr()),
        optimistic_slot:
          c["optimistic_header"]["slot"].getInt().Slot,
        optimistic_root:
          Eth2Digest.fromHex(c["optimistic_header"]["beacon_root"].getStr()))

    if step.hasKey"force_update":
      let s = step["force_update"]
      result.add TestStep(kind: TestStepKind.ForceUpdate,
                          current_slot: s["current_slot"].getInt().Slot,
                          checks: s["checks"].getChecks())
    elif step.hasKey"process_update":
      let
        s = step["process_update"]
        filename = s["update"].getStr()
        update = parseTest(path/filename & ".ssz_snappy", SSZ,
                           altair.LightClientUpdate)
      result.add TestStep(kind: TestStepKind.ProcessUpdate,
                          update: update,
                          current_slot: s["current_slot"].getInt().Slot,
                          checks: s["checks"].getChecks())
    else:
      doAssert false, "Unknown test step: " & $step

proc runTest(path: string) =
  test "Light client - Sync - " & path.relativePath(SszTestsDir):
    let
      (cfg, unknowns) = readRuntimeConfig(path/"config.yaml")
      meta = block:
        var s = openFileStream(path/"meta.yaml")
        defer: close(s)
        var res: TestMeta
        yaml.load(s, res)
        res
      genesis_validators_root =
        Eth2Digest.fromHex(meta.genesis_validators_root)
      trusted_block_root =
        Eth2Digest.fromHex(meta.trusted_block_root)

      bootstrap = parseTest(path/"bootstrap.ssz_snappy", SSZ,
                            altair.LightClientBootstrap)
      steps = loadSteps(path)
    doAssert unknowns.len == 0, "Unknown config constants: " & $unknowns

    var store =
      initialize_light_client_store(trusted_block_root, bootstrap).get
    for step in steps:
      case step.kind
      of TestStepKind.ForceUpdate:
        process_light_client_store_force_update(
          store, step.current_slot)
      of TestStepKind.ProcessUpdate:
        let res = process_light_client_update(
          store, step.update, step.current_slot,
          cfg, genesis_validators_root)
        check res.isOk
      check:
        store.finalized_header.slot == step.checks.finalized_slot
        hash_tree_root(store.finalized_header) == step.checks.finalized_root
        store.optimistic_header.slot == step.checks.optimistic_slot
        hash_tree_root(store.optimistic_header) == step.checks.optimistic_root

from std/strutils import contains

suite "EF - Light client - Sync" & preset():
  const presetPath = SszTestsDir/const_preset
  for kind, path in walkDir(presetPath, relative = true, checkDir = true):
    if path.contains("eip4844"):
      # this is a maybe temporary fork, maybe folded into capella soon
      continue
    let basePath =
      presetPath/path/"light_client"/"sync"/"pyspec_tests"
    if kind != pcDir or not dirExists(basePath):
      continue
    for kind, path in walkDir(basePath, relative = true, checkDir = true):
      let combinedPath = basePath/path
      runTest(basePath/path)
