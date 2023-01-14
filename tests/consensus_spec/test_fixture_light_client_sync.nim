# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[json, os, streams],
  # Status libraries
  stew/byteutils,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../../beacon_chain/spec/[forks, light_client_sync],
  # Test utilities
  ../testutil,
  ./fixtures_utils

type
  TestMeta = object
    genesis_validators_root: string
    trusted_block_root: string

  TestChecks = object
    finalized_slot: Slot
    finalized_beacon_root: Eth2Digest
    optimistic_slot: Slot
    optimistic_beacon_root: Eth2Digest

  TestStepKind {.pure.} = enum
    ForceUpdate
    ProcessUpdate

  TestStep = object
    case kind: TestStepKind
    of TestStepKind.ForceUpdate:
      discard
    of TestStepKind.ProcessUpdate:
      update: ForkedLightClientUpdate
    current_slot: Slot
    checks: TestChecks

proc loadSteps(path: string, fork_digests: ForkDigests): seq[TestStep] =
  let stepsYAML = readFile(path/"steps.yaml")
  let steps = yaml.loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    func getChecks(c: JsonNode): TestChecks =
      TestChecks(
        finalized_slot:
          c["finalized_header"]["slot"].getInt().Slot,
        finalized_beacon_root:
          Eth2Digest.fromHex(c["finalized_header"]["beacon_root"].getStr()),
        optimistic_slot:
          c["optimistic_header"]["slot"].getInt().Slot,
        optimistic_beacon_root:
          Eth2Digest.fromHex(c["optimistic_header"]["beacon_root"].getStr()))

    if step.hasKey"force_update":
      let s = step["force_update"]

      result.add TestStep(
        kind: TestStepKind.ForceUpdate,
        current_slot: s["current_slot"].getInt().Slot,
        checks: s["checks"].getChecks())
    elif step.hasKey"process_update":
      let
        s = step["process_update"]
        update_fork_digest = fork_digests.altair
        update_state_fork =
          fork_digests.stateForkForDigest(update_fork_digest)
            .expect("Unknown update fork " & $update_fork_digest)
        update_filename = s["update"].getStr()

      var update {.noinit.}: ForkedLightClientUpdate
      withLcDataFork(lcDataForkAtStateFork(update_state_fork)):
        when lcDataFork > LightClientDataFork.None:
          update = ForkedLightClientUpdate(kind: lcDataFork)
          update.forky(lcDataFork) = parseTest(
            path/update_filename & ".ssz_snappy", SSZ,
            lcDataFork.LightClientUpdate)
        else: raiseAssert "Unreachable update fork " & $update_fork_digest

      result.add TestStep(
        kind: TestStepKind.ProcessUpdate,
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
      fork_digests =
        ForkDigests.init(cfg, genesis_validators_root)
      bootstrap_fork_digest = fork_digests.altair
      store_fork_digest = fork_digests.altair
      bootstrap_state_fork =
        fork_digests.stateForkForDigest(bootstrap_fork_digest)
          .expect("Unknown bootstrap fork " & $bootstrap_fork_digest)
      store_state_fork =
        fork_digests.stateForkForDigest(store_fork_digest)
          .expect("Unknown store fork " & $store_fork_digest)
      steps = loadSteps(path, fork_digests)

    doAssert unknowns.len == 0, "Unknown config constants: " & $unknowns

    var bootstrap {.noinit.}: ForkedLightClientBootstrap
    withLcDataFork(lcDataForkAtStateFork(bootstrap_state_fork)):
      when lcDataFork > LightClientDataFork.None:
        bootstrap = ForkedLightClientBootstrap(kind: lcDataFork)
        bootstrap.forky(lcDataFork) = parseTest(
          path/"bootstrap.ssz_snappy", SSZ,
          lcDataFork.LightClientBootstrap)
      else: raiseAssert "Unsupported bootstrap fork " & $bootstrap_fork_digest

    var store {.noinit.}: ForkedLightClientStore
    withLcDataFork(lcDataForkAtStateFork(store_state_fork)):
      when lcDataFork > LightClientDataFork.None:
        store = ForkedLightClientStore(kind: lcDataFork)
        check bootstrap.kind <= lcDataFork
        let upgradedBootstrap = bootstrap.migratingToDataFork(lcDataFork)
        store.forky(lcDataFork) = initialize_light_client_store(
          trusted_block_root, bootstrap.forky(lcDataFork), cfg).get
      else: raiseAssert "Unreachable store fork " & $store_fork_digest

    for step in steps:
      withForkyStore(store):
        when lcDataFork > LightClientDataFork.None:
          case step.kind
          of TestStepKind.ForceUpdate:
            process_light_client_store_force_update(
              forkyStore, step.current_slot)
          of TestStepKind.ProcessUpdate:
            check step.update.kind <= lcDataFork
            let
              upgradedUpdate = step.update.migratingToDataFork(lcDataFork)
              res = process_light_client_update(
                forkyStore, upgradedUpdate.forky(lcDataFork), step.current_slot,
                cfg, genesis_validators_root)
            check res.isOk
        else: raiseAssert "Unreachable"

      withForkyStore(store):
        when lcDataFork > LightClientDataFork.None:
          let
            finalized_slot =
              forkyStore.finalized_header.beacon.slot
            finalized_beacon_root =
              hash_tree_root(forkyStore.finalized_header.beacon)
            optimistic_slot =
              forkyStore.optimistic_header.beacon.slot
            optimistic_beacon_root =
              hash_tree_root(forkyStore.optimistic_header.beacon)
          check:
            finalized_slot == step.checks.finalized_slot
            finalized_beacon_root == step.checks.finalized_beacon_root
            optimistic_slot == step.checks.optimistic_slot
            optimistic_beacon_root == step.checks.optimistic_beacon_root
        else: raiseAssert "Unreachable"

suite "EF - Light client - Sync" & preset():
  const presetPath = SszTestsDir/const_preset
  for kind, path in walkDir(presetPath, relative = true, checkDir = true):
    let basePath =
      presetPath/path/"light_client"/"sync"/"pyspec_tests"
    if kind != pcDir or not dirExists(basePath):
      continue
    for kind, path in walkDir(basePath, relative = true, checkDir = true):
      let combinedPath = basePath/path
      runTest(basePath/path)
