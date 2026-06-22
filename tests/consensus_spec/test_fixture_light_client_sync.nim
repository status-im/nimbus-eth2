# beacon_chain
# Copyright (c) 2022-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Standard library
  std/[json, streams, strutils],
  # Status libraries
  stew/byteutils,
  # Third-party
  yaml, yaml/tojson,
  # Beacon chain internals
  ../../beacon_chain/spec/[forks, light_client_sync],
  # Test utilities
  ../testutil,
  ./fixtures_utils, ./os_ops

type
  TestMeta = object
    genesis_validators_root: Eth2Digest
    trusted_block_root: Eth2Digest
    fork_digests: ForkDigests
    bootstrap_fork_digest: ForkDigest
    store_consensus_fork: ConsensusFork

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

func consensusForkForVersion(
    cfg: RuntimeConfig, version: Version): Opt[ConsensusFork] =
  static: doAssert ConsensusFork.high == ConsensusFork.Heze
  if   version == cfg.HEZE_FORK_VERSION:      ok(ConsensusFork.Heze)
  elif version == cfg.GLOAS_FORK_VERSION:     ok(ConsensusFork.Gloas)
  elif version == cfg.FULU_FORK_VERSION:      ok(ConsensusFork.Fulu)
  elif version == cfg.ELECTRA_FORK_VERSION:   ok(ConsensusFork.Electra)
  elif version == cfg.DENEB_FORK_VERSION:     ok(ConsensusFork.Deneb)
  elif version == cfg.CAPELLA_FORK_VERSION:   ok(ConsensusFork.Capella)
  elif version == cfg.BELLATRIX_FORK_VERSION: ok(ConsensusFork.Bellatrix)
  elif version == cfg.ALTAIR_FORK_VERSION:    ok(ConsensusFork.Altair)
  elif version == cfg.GENESIS_FORK_VERSION:   ok(ConsensusFork.Phase0)
  else: err()

func getStoreConsensusFork(
    store_fork_version: Option[string], store_fork_digest: Option[string],
    cfg: RuntimeConfig, fork_digests: ForkDigests
): ConsensusFork {.raises: [ValueError].} =
  if store_fork_version.isSome:
    let version = Version(distinctBase(Version).fromHex(store_fork_version.get))
    cfg.consensusForkForVersion(version)
      .expect("Unknown store fork version " & $version)
  elif store_fork_digest.isSome:
    let digest =
      ForkDigest(distinctBase(ForkDigest).fromHex(store_fork_digest.get))
    fork_digests.consensusForkForDigest(digest)
      .expect("Unknown store fork " & $digest)
  else:
    ConsensusFork.Altair

proc loadSteps(
    path: string,
    cfg: RuntimeConfig,
    fork_digests: ForkDigests
): seq[TestStep] {.raises: [KeyError, ValueError].} =
  let stepsYAML = os_ops.readFile(path/"steps.yaml")
  let steps = loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    func getChecks(c: JsonNode): TestChecks {.raises: [KeyError].} =
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

      var update: ForkedLightClientUpdate
      withLcDataFork(lcDataForkAtConsensusFork(update_consensus_fork)):
        when lcDataFork > LightClientDataFork.None:
          update = ForkedLightClientUpdate.init(parseTest(
            path/update_filename & ".ssz_snappy", SSZ,
            lcDataFork.LightClientUpdate))
        else: raiseAssert "Unreachable update fork " & $update_fork_digest

      result.add TestStep(
        kind: TestStepKind.ProcessUpdate,
        update: update,
        current_slot: s["current_slot"].getInt().Slot,
        checks: s["checks"].getChecks())
    elif step.hasKey"upgrade_store":
      let
        s = step["upgrade_store"]
        store_consensus_fork = getStoreConsensusFork(
          store_fork_version =
            if s.hasKey"store_fork_version":
              some(s["store_fork_version"].getStr())
            else:
              none(string),
          store_fork_digest =
            if s.hasKey"store_fork_digest":
              some(s["store_fork_digest"].getStr())
            else:
              none(string),
          cfg, fork_digests)

      result.add TestStep(
        kind: TestStepKind.UpgradeStore,
        store_data_fork: lcDataForkAtConsensusFork(store_consensus_fork),
        checks: s["checks"].getChecks())
    else:
      doAssert false, "Unknown test step: " & $step

proc runTest(suiteName, path: string) =
  let relativePathComponent = path.relativeTestPathComponent()
  test "Light client - Sync - " & relativePathComponent:
    # Reduce stack size by making this a `proc`
    proc loadTestMeta(): (RuntimeConfig, TestMeta)
        {.raises: [IOError, OSError, PresetFileError,
                   PresetIncompatibleError, ValueError,
                   YamlConstructionError, YamlParserError].} =
      let (cfg, _) = readRuntimeConfig(path/"config.yaml")

      type TestMetaYaml {.sparse.} = object
        genesis_validators_root: string
        trusted_block_root: string
        bootstrap_fork_digest: Option[string]
        store_fork_digest: Option[string]
        store_fork_version: Option[string]
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
        store_consensus_fork = getStoreConsensusFork(
          meta.store_fork_version, meta.store_fork_digest,
          cfg, fork_digests)

      (cfg, TestMeta(
        genesis_validators_root: genesis_validators_root,
        trusted_block_root: trusted_block_root,
        fork_digests: fork_digests,
        bootstrap_fork_digest: bootstrap_fork_digest,
        store_consensus_fork: store_consensus_fork))

    let
      (cfg, meta) = loadTestMeta()
      steps = loadSteps(path, cfg, meta.fork_digests)

    # Reduce stack size by making this a `proc`
    proc loadBootstrap(): ForkedLightClientBootstrap =
      let bootstrap_consensus_fork =
        meta.fork_digests.consensusForkForDigest(meta.bootstrap_fork_digest)
          .expect("Unknown bootstrap fork " & $meta.bootstrap_fork_digest)
      var bootstrap: ForkedLightClientBootstrap
      withLcDataFork(lcDataForkAtConsensusFork(bootstrap_consensus_fork)):
        when lcDataFork > LightClientDataFork.None:
          bootstrap = ForkedLightClientBootstrap.init(parseTest(
            path/"bootstrap.ssz_snappy", SSZ,
            lcDataFork.LightClientBootstrap))
        else:
          raiseAssert "Unknown bootstrap fork " & $meta.bootstrap_fork_digest
      bootstrap

    # Reduce stack size by making this a `proc`
    proc initializeStore(
        bootstrap: ref ForkedLightClientBootstrap): ForkedLightClientStore =
      var store: ForkedLightClientStore
      withLcDataFork(lcDataForkAtConsensusFork(meta.store_consensus_fork)):
        when lcDataFork > LightClientDataFork.None:
          bootstrap[].migrateToDataFork(lcDataFork, cfg)
          store = ForkedLightClientStore.init(initialize_light_client_store(
            meta.trusted_block_root, bootstrap[].forky(lcDataFork), cfg).get)
        else:
          raiseAssert "Unreachable store fork " & $meta.store_consensus_fork
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
              upgradedUpdate = step.update.migratingToDataFork(lcDataFork, cfg)
              res = process_light_client_update(
                forkyStore, upgradedUpdate.forky(lcDataFork), step.current_slot,
                cfg, meta.genesis_validators_root)
            check res.isOk
          of TestStepKind.UpgradeStore:
            check step.store_data_fork >= lcDataFork
            withLcDataFork(step.store_data_fork):
              when lcDataFork > LightClientDataFork.None:
                store.migrateToDataFork(lcDataFork, cfg)
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
  for kind, forkPath in walkDir(presetPath, relative = true, checkDir = true):
    let basePath =
      presetPath/forkPath/"light_client"/"sync"/"pyspec_tests"
    if kind != pcDir or not dirExists(basePath):
      continue
    for kind, path in walkDir(basePath, relative = true, checkDir = true):
      runTest(suiteName, basePath/path)
