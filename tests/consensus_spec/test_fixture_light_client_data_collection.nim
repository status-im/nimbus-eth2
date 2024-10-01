# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Standard library
  std/[json, sequtils],
  # Status libraries
  stew/byteutils,
  chronicles,
  taskpools,
  # Third-party
  yaml/tojson,
  # Beacon chain internals
  ../../beacon_chain/beacon_chain_db,
  ../../beacon_chain/consensus_object_pools/[block_clearance, block_quarantine],
  ../../beacon_chain/spec/forks,
  # Test utilities
  ../testutil, ../testbcutil,
  ./fixtures_utils, ./os_ops

type
  TestStepKind {.pure.} = enum
    NewBlock
    NewHead

  NewHeadChecks = object
    latestFinalizedCheckpoint: Checkpoint
    bootstraps: Table[Eth2Digest, ForkedLightClientBootstrap]
    bestUpdates: Table[SyncCommitteePeriod, ForkedLightClientUpdate]
    latestFinalityUpdate: ForkedLightClientFinalityUpdate
    latestOptimisticUpdate: ForkedLightClientOptimisticUpdate

  TestStep = object
    case kind: TestStepKind
    of TestStepKind.NewBlock:
      blck: ForkedSignedBeaconBlock
    of TestStepKind.NewHead:
      headBlockRoot: Eth2Digest
      checks: NewHeadChecks

func `==`(a, b: SomeForkedLightClientObject): bool =
  a.kind == b.kind and withForkyObject(a, (
    when lcDataFork > LightClientDataFork.None:
      forkyObject == b.forky(lcDataFork)
    else:
      true))

proc loadForked[T: not Opt](
    t: typedesc[T],
    s: JsonNode,
    path: string,
    fork_digests: ForkDigests): T {.raises: [ValueError].} =
  if s == nil:
    when T is SomeForkedLightClientObject:
      return default(T)
    else:
      raiseAssert "Unexpected nil JSON node"
  let
    fork_digest = ForkDigest distinctBase(ForkDigest)
      .fromHex(s["fork_digest"].getStr())
    consensusFork = fork_digests.consensusForkForDigest(fork_digest)
      .expect("Unknown fork " & $fork_digest)
    filename = s["data"].getStr()
  when T is SomeForkedLightClientObject:
    withLcDataFork(lcDataForkAtConsensusFork(consensusFork)):
      when lcDataFork > LightClientDataFork.None:
        T.init(parseTest(
          path/filename & ".ssz_snappy", SSZ, T.Forky(lcDataFork)))
      else: raiseAssert $consensusFork & " does not support LC data"
  else:
    withConsensusFork(consensusFork):
      T.init(parseTest(
        path/filename & ".ssz_snappy", SSZ, T.Forky(consensusFork)))

proc loadSteps(
    path: string,
    fork_digests: ForkDigests
): seq[TestStep] {.raises: [
    IOError, KeyError, ValueError, YamlConstructionError, YamlParserError].} =
  template loadForked[T](t: typedesc[T], s: JsonNode): T =
    loadForked(t, s, path, fork_digests)

  let stepsYAML = os_ops.readFile(path/"steps.yaml")
  let steps = loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    if step.hasKey"new_block":
      let s = step["new_block"]
      result.add TestStep(
        kind: TestStepKind.NewBlock,
        blck: ForkedSignedBeaconBlock.loadForked(s))
    elif step.hasKey"new_head":
      let
        s = step["new_head"]
        checks = s["checks"]
      result.add TestStep(
        kind: TestStepKind.NewHead,
        headBlockRoot: Eth2Digest.fromHex(s["head_block_root"].getStr()),
        checks: NewHeadChecks(
          latestFinalizedCheckpoint: Checkpoint(
            epoch: Epoch(
              checks["latest_finalized_checkpoint"]["epoch"].getInt()),
            root: Eth2Digest.fromHex(
              checks["latest_finalized_checkpoint"]["root"].getStr())),
          bootstraps: checks["bootstraps"].foldl((block:
            check: not a.hasKeyOrPut(
              Eth2Digest.fromHex(b["block_root"].getStr()),
              ForkedLightClientBootstrap.loadForked(b{"bootstrap"}))
            a), newTable[Eth2Digest, ForkedLightClientBootstrap]())[],
          bestUpdates: checks["best_updates"].foldl((block:
            check: not a.hasKeyOrPut(
              SyncCommitteePeriod(b["period"].getInt()),
              ForkedLightClientUpdate.loadForked(b{"update"}))
            a), newTable[SyncCommitteePeriod, ForkedLightClientUpdate]())[],
          latestFinalityUpdate: ForkedLightClientFinalityUpdate
            .loadForked(checks{"latest_finality_update"}),
          latestOptimisticUpdate: ForkedLightClientOptimisticUpdate
            .loadForked(checks{"latest_optimistic_update"})))
    else:
      raiseAssert "Unknown test step: " & $step

proc runTest(suiteName, path: string, consensusFork: static ConsensusFork) =
  let relativePathComponent = path.relativeTestPathComponent()
  test "Light client - Data collection - " & relativePathComponent:
    let
      (cfg, _) = readRuntimeConfig(path/"config.yaml")
      initial_state = loadForkedState(
        path/"initial_state.ssz_snappy", consensusFork)
      db = BeaconChainDB.new("", cfg = cfg, inMemory = true)
    defer: db.close()
    ChainDAGRef.preInit(db, initial_state[])

    let
      validatorMonitor = newClone(ValidatorMonitor.init(false, false))
      dag = ChainDAGRef.init(cfg, db, validatorMonitor, {},
        lcDataConfig = LightClientDataConfig(
          serve: true, importMode: LightClientDataImportMode.Full))
      rng = HmacDrbgContext.new()
      taskpool = TaskPool.new()
    var
      verifier = BatchVerifier.init(rng, taskpool)
      quarantine = newClone(Quarantine.init())

    let steps = loadSteps(path, dag.forkDigests[])
    for i, step in steps:
      case step.kind
      of TestStepKind.NewBlock:
        checkpoint $i & " new_block: " & $shortLog(step.blck.toBlockId())
        let added = withBlck(step.blck):
          const nilCallback = (consensusFork.OnBlockAddedCallback)(nil)
          dag.addHeadBlock(verifier, forkyBlck, nilCallback)
        check: added.isOk()
      of TestStepKind.NewHead:
        let blck = dag.getBlockRef(step.headBlockRoot)
        check blck.isSome
        checkpoint $i & " new_head: " & $shortLog(blck.get.bid)
        dag.updateHead(blck.get, quarantine[], knownValidators = [])
        if dag.needStateCachesAndForkChoicePruning():
          dag.pruneStateCachesDAG()
        check:
          step.checks.latestFinalizedCheckpoint.epoch ==
            dag.finalizedHead.slot.epoch
          step.checks.latestFinalizedCheckpoint.root == (
            if dag.finalizedHead.blck.slot != GENESIS_SLOT:
              dag.finalizedHead.blck.root
            else:
              ZERO_HASH)
          step.checks.bootstraps.pairs().toSeq().allIt:
            dag.getLightClientBootstrap(it[0]) == it[1]
          step.checks.bestUpdates.pairs().toSeq().allIt:
            dag.getLightClientUpdateForPeriod(it[0]) == it[1]
          step.checks.latestFinalityUpdate ==
            dag.getLightClientFinalityUpdate()
          step.checks.latestOptimisticUpdate ==
            dag.getLightClientOptimisticUpdate()

suite "EF - Light client - Data collection" & preset():
  const presetPath = SszTestsDir/const_preset
  for kind, path in walkDir(presetPath, relative = true, checkDir = true):
    let testsPath =
      presetPath/path/"light_client"/"data_collection"/"pyspec_tests"
    if kind != pcDir or not dirExists(testsPath):
      continue
    let consensusFork = forkForPathComponent(path).valueOr:
      let relativePathComponent = path.relativeTestPathComponent()
      test "Light client - Data collection - " & relativePathComponent:
        skip()
      continue
    for kind, path in walkDir(testsPath, relative = true, checkDir = true):
      withConsensusFork(consensusFork):
        runTest(suiteName, testsPath/path, consensusFork)
