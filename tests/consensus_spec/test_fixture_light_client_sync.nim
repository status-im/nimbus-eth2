# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[json, streams],
  # Status libraries
  stew/byteutils,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../../beacon_chain/spec/[forks, light_client_sync],
  # Test utilities
  ../testutil,
  ./fixtures_utils, ./os_ops

type
  TestMeta = object
    genesis_validators_root: Eth2Digest
    trusted_block_root: Eth2Digest
    fork_digests: ForkDigests
    bootstrap_fork_digest: ForkDigest
    store_fork_digest: ForkDigest

  TestChecks = object
    finalized_slot: Slot
    finalized_beacon_root: Eth2Digest
    finalized_execution_root: Eth2Digest
    optimistic_slot: Slot
    optimistic_beacon_root: Eth2Digest
    optimistic_execution_root: Eth2Digest

  TestStepKind {.pure.} = enum
    ForceUpdate
    ProcessUpdate
    UpgradeStore

  TestStep = object
    case kind: TestStepKind
    of TestStepKind.ForceUpdate:
      discard
    of TestStepKind.ProcessUpdate:
      update: ForkedLightClientUpdate
    of TestStepKind.UpgradeStore:
      store_data_fork: LightClientDataFork
    current_slot: Slot
    checks: TestChecks

proc loadSteps(path: string, fork_digests: ForkDigests): seq[TestStep] =
  let stepsYAML = os_ops.readFile(path/"steps.yaml")
  let steps = yaml.loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    func getChecks(c: JsonNode): TestChecks =
      TestChecks(
        finalized_slot:
          c["finalized_header"]["slot"].getInt().Slot,
        finalized_beacon_root:
          Eth2Digest.fromHex(c["finalized_header"]["beacon_root"].getStr()),
        finalized_execution_root:
          Eth2Digest.fromHex(c["finalized_header"]{"execution_root"}.getStr()),
        optimistic_slot:
          c["optimistic_header"]["slot"].getInt().Slot,
        optimistic_beacon_root:
          Eth2Digest.fromHex(c["optimistic_header"]["beacon_root"].getStr()),
        optimistic_execution_root:
          Eth2Digest.fromHex(c["optimistic_header"]{"execution_root"}.getStr()))

    if step.hasKey"force_update":
      let s = step["force_update"]

      result.add TestStep(
        kind: TestStepKind.ForceUpdate,
        current_slot: s["current_slot"].getInt().Slot,
        checks: s["checks"].getChecks())
    elif step.hasKey"process_update":
      let
        s = step["process_update"]
        update_fork_digest =
          distinctBase(ForkDigest).fromHex(s{"update_fork_digest"}.getStr(
            distinctBase(fork_digests.altair).toHex())).ForkDigest
        update_consensus_fork =
          fork_digests.consensusForkForDigest(update_fork_digest)
            .expect("Unknown update fork " & $update_fork_digest)
        update_filename = s["update"].getStr()

      var update {.noinit.}: ForkedLightClientUpdate
      withLcDataFork(lcDataForkAtConsensusFork(update_consensus_fork)):
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
    elif step.hasKey"upgrade_store":
      let
        s = step["upgrade_store"]
        store_fork_digest =
          distinctBase(ForkDigest).fromHex(
            s["store_fork_digest"].getStr()).ForkDigest
        store_consensus_fork =
          fork_digests.consensusForkForDigest(store_fork_digest)
            .expect("Unknown store fork " & $store_fork_digest)

      result.add TestStep(
        kind: TestStepKind.UpgradeStore,
        store_data_fork: lcDataForkAtConsensusFork(store_consensus_fork),
        checks: s["checks"].getChecks())
    else:
      doAssert false, "Unknown test step: " & $step

proc runTest(path: string) =
  test "Light client - Sync - " & path.relativePath(SszTestsDir):
    # Reduce stack size by making this a `proc`
    proc loadTestMeta(): (RuntimeConfig, TestMeta) =
      let (cfg, unknowns) = readRuntimeConfig(path/"config.yaml")

      doAssert unknowns.len == 0, "Unknown config constants: " & $unknowns

      type TestMetaYaml {.sparse.} = object
        genesis_validators_root: string
        trusted_block_root: string
        bootstrap_fork_digest: Option[string]
        store_fork_digest: Option[string]
      let
        meta = block:
          var s = openFileStream(path/"meta.yaml")
          defer: close(s)
          var res: TestMetaYaml
          yaml.load(s, res)
          res
        genesis_validators_root =
          Eth2Digest.fromHex(meta.genesis_validators_root)
        trusted_block_root =
          Eth2Digest.fromHex(meta.trusted_block_root)
        fork_digests =
          ForkDigests.init(cfg, genesis_validators_root)
        bootstrap_fork_digest =
          distinctBase(ForkDigest).fromHex(meta.bootstrap_fork_digest.get(
            distinctBase(fork_digests.altair).toHex())).ForkDigest
        store_fork_digest =
          distinctBase(ForkDigest).fromHex(meta.store_fork_digest.get(
            distinctBase(fork_digests.altair).toHex())).ForkDigest

      (cfg, TestMeta(
        genesis_validators_root: genesis_validators_root,
        trusted_block_root: trusted_block_root,
        fork_digests: fork_digests,
        bootstrap_fork_digest: bootstrap_fork_digest,
        store_fork_digest: store_fork_digest))

    let
      (cfg, meta) = loadTestMeta()
      steps = loadSteps(path, meta.fork_digests)

    # Reduce stack size by making this a `proc`
    proc loadBootstrap(): ForkedLightClientBootstrap =
      let bootstrap_consensus_fork =
        meta.fork_digests.consensusForkForDigest(meta.bootstrap_fork_digest)
          .expect("Unknown bootstrap fork " & $meta.bootstrap_fork_digest)
      var bootstrap {.noinit.}: ForkedLightClientBootstrap
      withLcDataFork(lcDataForkAtConsensusFork(bootstrap_consensus_fork)):
        when lcDataFork > LightClientDataFork.None:
          bootstrap = ForkedLightClientBootstrap(kind: lcDataFork)
          bootstrap.forky(lcDataFork) = parseTest(
            path/"bootstrap.ssz_snappy", SSZ,
            lcDataFork.LightClientBootstrap)
        else:
          raiseAssert "Unknown bootstrap fork " & $meta.bootstrap_fork_digest
      bootstrap

    # Reduce stack size by making this a `proc`
    proc initializeStore(
        bootstrap: ref ForkedLightClientBootstrap): ForkedLightClientStore =
      let store_consensus_fork =
        meta.fork_digests.consensusForkForDigest(meta.store_fork_digest)
          .expect("Unknown store fork " & $meta.store_fork_digest)
      var store {.noinit.}: ForkedLightClientStore
      withLcDataFork(lcDataForkAtConsensusFork(store_consensus_fork)):
        when lcDataFork > LightClientDataFork.None:
          store = ForkedLightClientStore(kind: lcDataFork)
          bootstrap[].migrateToDataFork(lcDataFork)
          store.forky(lcDataFork) = initialize_light_client_store(
            meta.trusted_block_root, bootstrap[].forky(lcDataFork), cfg).get
        else: raiseAssert "Unreachable store fork " & $meta.store_fork_digest
      store

    let bootstrap = newClone(loadBootstrap())
    var store = initializeStore(bootstrap)

    # Reduce stack size by making this a `proc`
    proc processStep(step: TestStep) =
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
                cfg, meta.genesis_validators_root)
            check res.isOk
          of TestStepKind.UpgradeStore:
            check step.store_data_fork >= lcDataFork
            withLcDataFork(step.store_data_fork):
              when lcDataFork > LightClientDataFork.None:
                store.migrateToDataFork(lcDataFork)
        else: raiseAssert "Unreachable"

      withForkyStore(store):
        when lcDataFork > LightClientDataFork.None:
          let
            finalized_slot =
              forkyStore.finalized_header.beacon.slot
            finalized_beacon_root =
              hash_tree_root(forkyStore.finalized_header.beacon)
            finalized_execution_root =
              when lcDataFork >= LightClientDataFork.Capella:
                get_lc_execution_root(forkyStore.finalized_header, cfg)
              else:
                ZERO_HASH
            optimistic_slot =
              forkyStore.optimistic_header.beacon.slot
            optimistic_beacon_root =
              hash_tree_root(forkyStore.optimistic_header.beacon)
            optimistic_execution_root =
              when lcDataFork >= LightClientDataFork.Capella:
                get_lc_execution_root(forkyStore.optimistic_header, cfg)
              else:
                ZERO_HASH
          check:
            finalized_slot == step.checks.finalized_slot
            finalized_beacon_root == step.checks.finalized_beacon_root
            finalized_execution_root == step.checks.finalized_execution_root
            optimistic_slot == step.checks.optimistic_slot
            optimistic_beacon_root == step.checks.optimistic_beacon_root
            optimistic_execution_root == step.checks.optimistic_execution_root
        else: raiseAssert "Unreachable"

    for step in steps:
      processStep(step)

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
