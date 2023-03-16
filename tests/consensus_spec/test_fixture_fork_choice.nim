# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  std/[json, sequtils, strutils, tables],
  # Status libraries
  stew/results, chronicles,
  eth/keys, taskpools,
  # Internals
  ../../beacon_chain/spec/[helpers, forks, state_transition_block],
  ../../beacon_chain/spec/datatypes/[
    base,
    phase0, altair, bellatrix],
  ../../beacon_chain/fork_choice/[fork_choice, fork_choice_types],
  ../../beacon_chain/[beacon_chain_db, beacon_clock],
  ../../beacon_chain/consensus_object_pools/[
    blockchain_dag, block_clearance, block_quarantine, spec_cache],
  # Third-party
  yaml,
  # Test
  ../testutil, ../testdbutil,
  ./fixtures_utils, ./os_ops

# Test format described at https://github.com/ethereum/consensus-specs/tree/v1.2.0-rc.1/tests/formats/fork_choice
# Note that our implementation has been optimized with "ProtoArray"
# instead of following the spec (in particular the "store").

type
  OpKind = enum
    opOnTick
    opOnAttestation
    opOnBlock
    opOnMergeBlock
    opOnAttesterSlashing
    opInvalidateRoot
    opChecks

  Operation = object
    valid: bool
    # variant specific fields
    case kind: OpKind
    of opOnTick:
      tick: int
    of opOnAttestation:
      att: Attestation
    of opOnBlock:
      blck: ForkedSignedBeaconBlock
    of opOnMergeBlock:
      powBlock: PowBlock
    of opOnAttesterSlashing:
      attesterSlashing: AttesterSlashing
    of opInvalidateRoot:
      invalidatedRoot: Eth2Digest
      latestValidHash: Eth2Digest
    of opChecks:
      checks: JsonNode

from ../../beacon_chain/spec/datatypes/capella import
  BeaconBlock, BeaconState, SignedBeaconBlock

from ../../beacon_chain/spec/datatypes/deneb import
  BeaconBlock, BeaconState, SignedBeaconBlock

proc initialLoad(
    path: string, db: BeaconChainDB,
    StateType, BlockType: typedesc
): tuple[dag: ChainDAGRef, fkChoice: ref ForkChoice] =
  let
    forkedState = loadForkedState(
      path/"anchor_state.ssz_snappy",
      StateType.toFork)

    blck = parseTest(
      path/"anchor_block.ssz_snappy",
      SSZ, BlockType)

  when BlockType is deneb.BeaconBlock:
    let signedBlock = ForkedSignedBeaconBlock.init(deneb.SignedBeaconBlock(
      message: blck,
      # signature: - unused as it's trusted
      root: hash_tree_root(blck)
    ))
  elif BlockType is capella.BeaconBlock:
    let signedBlock = ForkedSignedBeaconBlock.init(capella.SignedBeaconBlock(
      message: blck,
      # signature: - unused as it's trusted
      root: hash_tree_root(blck)
    ))
  elif BlockType is bellatrix.BeaconBlock:
    let signedBlock = ForkedSignedBeaconBlock.init(bellatrix.SignedBeaconBlock(
      message: blck,
      # signature: - unused as it's trusted
      root: hash_tree_root(blck)
    ))
  elif BlockType is altair.BeaconBlock:
    let signedBlock = ForkedSignedBeaconBlock.init(altair.SignedBeaconBlock(
      message: blck,
      # signature: - unused as it's trusted
      root: hash_tree_root(blck)
    ))
  elif BlockType is phase0.BeaconBlock:
    let signedBlock = ForkedSignedBeaconBlock.init(phase0.SignedBeaconBlock(
      message: blck,
      # signature: - unused as it's trusted
      root: hash_tree_root(blck)
    ))
  else: {.error: "Unknown block fork: " & name(BlockType).}

  ChainDAGRef.preInit(db, forkedState[])

  let
    validatorMonitor = newClone(ValidatorMonitor.init())
    dag = ChainDAGRef.init(
      forkedState[].kind.genesisTestRuntimeConfig, db, validatorMonitor,
      {enableTestFeatures, experimental})
    fkChoice = newClone(ForkChoice.init(
      dag.getFinalizedEpochRef(),
      dag.finalizedHead.blck,
      true,
    ))

  (dag, fkChoice)

proc loadOps(path: string, fork: ConsensusFork): seq[Operation] =
  let stepsYAML = os_ops.readFile(path/"steps.yaml")
  let steps = yaml.loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    if step.hasKey"tick":
      result.add Operation(kind: opOnTick,
        tick: step["tick"].getInt())
    elif step.hasKey"attestation":
      let filename = step["attestation"].getStr()
      let att = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, Attestation
      )
      result.add Operation(kind: opOnAttestation,
        att: att)
    elif step.hasKey"block":
      let filename = step["block"].getStr()
      case fork
      of ConsensusFork.Phase0:
        let blck = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, phase0.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blck: ForkedSignedBeaconBlock.init(blck))
      of ConsensusFork.Altair:
        let blck = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, altair.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blck: ForkedSignedBeaconBlock.init(blck))
      of ConsensusFork.Bellatrix:
        let blck = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, bellatrix.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blck: ForkedSignedBeaconBlock.init(blck))
      of ConsensusFork.Capella:
        let blck = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, capella.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blck: ForkedSignedBeaconBlock.init(blck))
      of ConsensusFork.Deneb:
        let blck = parseTest(
          path/filename & ".ssz_snappy",
          SSZ, deneb.SignedBeaconBlock
        )
        result.add Operation(kind: opOnBlock,
          blck: ForkedSignedBeaconBlock.init(blck))
    elif step.hasKey"attester_slashing":
      let filename = step["attester_slashing"].getStr()
      let attesterSlashing = parseTest(
        path/filename & ".ssz_snappy",
        SSZ, AttesterSlashing
      )
      result.add Operation(kind: opOnAttesterSlashing,
        attesterSlashing: attesterSlashing)
    elif step.hasKey"payload_status":
      if step["payload_status"]["status"].getStr() == "INVALID":
        result.add Operation(kind: opInvalidateRoot,
          valid: true,
          invalidatedRoot: Eth2Digest.fromHex(step["block_hash"].getStr()),
          latestValidHash: Eth2Digest.fromHex(
            step["payload_status"]["latest_valid_hash"].getStr()))
    elif step.hasKey"checks":
      result.add Operation(kind: opChecks,
        checks: step["checks"])
    else:
      doAssert false, "Unknown test step: " & $step

    if step.hasKey"valid":
      doAssert step.len == 2
      result[^1].valid = step["valid"].getBool()
    elif not step.hasKey"checks" and not step.hasKey"payload_status":
      doAssert step.len == 1
      result[^1].valid = true

proc stepOnBlock(
       dag: ChainDAGRef,
       fkChoice: ref ForkChoice,
       verifier: var BatchVerifier,
       state: var ForkedHashedBeaconState,
       stateCache: var StateCache,
       signedBlock: ForkySignedBeaconBlock,
       time: BeaconTime,
       invalidatedRoots: Table[Eth2Digest, Eth2Digest]):
       Result[BlockRef, VerifierError] =
  # 1. Move state to proper slot.
  doAssert dag.updateState(
    state,
    dag.getBlockIdAtSlot(time.slotOrZero).expect("block exists"),
    save = false,
    stateCache
  )

  # 2. Add block to DAG
  when signedBlock is phase0.SignedBeaconBlock:
    type TrustedBlock = phase0.TrustedSignedBeaconBlock
  elif signedBlock is altair.SignedBeaconBlock:
    type TrustedBlock = altair.TrustedSignedBeaconBlock
  elif signedBlock is bellatrix.SignedBeaconBlock:
    type TrustedBlock = bellatrix.TrustedSignedBeaconBlock
  elif signedBlock is capella.SignedBeaconBlock:
    type TrustedBlock = capella.TrustedSignedBeaconBlock
  elif signedBlock is deneb.SignedBeaconBlock:
    type TrustedBlock = deneb.TrustedSignedBeaconBlock
  else:
    doAssert false, "Unknown TrustedSignedBeaconBlock fork"


  # In normal Nimbus flow, for this (effectively) newPayload-based INVALID, it
  # is checked even before entering the DAG, by the block processor. Currently
  # the optimistic sync test(s) don't include a later-fcU-INVALID case. Whilst
  # this wouldn't be part of this check, presumably, their FC test vector step
  # would also have `true` validity because it'd not be known they weren't, so
  # adding this mock of the block processor is realistic and sufficient.
  when not (
      signedBlock is phase0.SignedBeaconBlock or
      signedBlock is altair.SignedBeaconBlock):
    let executionPayloadHash =
      signedBlock.message.body.execution_payload.block_hash
    if executionPayloadHash in invalidatedRoots:
      # Mocks fork choice INVALID list application. These tests sequence this
      # in a way the block processor does not, specifying each payload_status
      # before the block itself, while Nimbus fork choice treats invalidating
      # a non-existent block root as a no-op and does not remember it for the
      # future.
      let lvh = invalidatedRoots.getOrDefault(
        executionPayloadHash, static(default(Eth2Digest)))
      fkChoice[].mark_root_invalid(dag.getEarliestInvalidBlockRoot(
        signedBlock.message.parent_root, lvh, executionPayloadHash))

      return err VerifierError.Invalid

  let blockAdded = dag.addHeadBlock(verifier, signedBlock) do (
      blckRef: BlockRef, signedBlock: TrustedBlock,
      epochRef: EpochRef, unrealized: FinalityCheckpoints):

    # 3. Update fork choice if valid
    let status = fkChoice[].process_block(
      dag, epochRef, blckRef, unrealized, signedBlock.message, time)
    doAssert status.isOk()

    # 4. Update DAG with new head
    var quarantine = Quarantine.init()
    let newHead = fkChoice[].get_head(dag, time).get()
    dag.updateHead(dag.getBlockRef(newHead).get(), quarantine, [])
    if dag.needStateCachesAndForkChoicePruning():
      dag.pruneStateCachesDAG()
      let pruneRes = fkChoice[].prune()
      doAssert pruneRes.isOk()

  blockAdded

proc stepChecks(
       checks: JsonNode,
       dag: ChainDAGRef,
       fkChoice: ref ForkChoice,
       time: BeaconTime
     ) =
  doAssert checks.len >= 1, "No checks found"
  for check, val in checks:
    if check == "time":
      doAssert time.ns_since_genesis == val.getInt().seconds.nanoseconds()
      doAssert fkChoice.checkpoints.time.slotOrZero == time.slotOrZero
    elif check == "head":
      let headRoot = fkChoice[].get_head(dag, time).get()
      let headRef = dag.getBlockRef(headRoot).get()
      doAssert headRef.slot == Slot(val["slot"].getInt())
      doAssert headRef.root == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "justified_checkpoint":
      let checkpointRoot = fkChoice.checkpoints.justified.checkpoint.root
      let checkpointEpoch = fkChoice.checkpoints.justified.checkpoint.epoch
      doAssert checkpointEpoch == Epoch(val["epoch"].getInt())
      doAssert checkpointRoot == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "justified_checkpoint_root": # undocumented check
      let checkpointRoot = fkChoice.checkpoints.justified.checkpoint.root
      doAssert checkpointRoot == Eth2Digest.fromHex(val.getStr())
    elif check == "finalized_checkpoint":
      let checkpointRoot = fkChoice.checkpoints.finalized.root
      let checkpointEpoch = fkChoice.checkpoints.finalized.epoch
      doAssert checkpointEpoch == Epoch(val["epoch"].getInt())
      doAssert checkpointRoot == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "best_justified_checkpoint":
      let checkpointRoot = fkChoice.checkpoints.best_justified.root
      let checkpointEpoch = fkChoice.checkpoints.best_justified.epoch
      doAssert checkpointEpoch == Epoch(val["epoch"].getInt())
      doAssert checkpointRoot == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "proposer_boost_root":
      doAssert fkChoice.checkpoints.proposer_boost_root ==
        Eth2Digest.fromHex(val.getStr())
    elif check == "genesis_time":
      # We do not store genesis in fork choice..
      discard
    else:
      doAssert false, "Unsupported check '" & $check & "'"

proc doRunTest(path: string, fork: ConsensusFork) =
  let db = BeaconChainDB.new("", inMemory = true)
  defer:
    db.close()

  let stores =
    case fork
    of ConsensusFork.Deneb:
      initialLoad(path, db, deneb.BeaconState, deneb.BeaconBlock)
    of ConsensusFork.Capella:
      initialLoad(path, db, capella.BeaconState, capella.BeaconBlock)
    of ConsensusFork.Bellatrix:
      initialLoad(path, db, bellatrix.BeaconState, bellatrix.BeaconBlock)
    of ConsensusFork.Altair:
      initialLoad(path, db, altair.BeaconState, altair.BeaconBlock)
    of ConsensusFork.Phase0:
      initialLoad(path, db, phase0.BeaconState, phase0.BeaconBlock)

  var
    taskpool = Taskpool.new()
    verifier = BatchVerifier(rng: keys.newRng(), taskpool: taskpool)

  let steps = loadOps(path, fork)
  var time = stores.fkChoice.checkpoints.time
  var invalidatedRoots: Table[Eth2Digest, Eth2Digest]

  let state = newClone(stores.dag.headState)
  var stateCache = StateCache()

  for step in steps:
    case step.kind
    of opOnTick:
      time = BeaconTime(ns_since_genesis: step.tick.seconds.nanoseconds)
      let status = stores.fkChoice[].update_time(stores.dag, time)
      doAssert status.isOk == step.valid
    of opOnAttestation:
      let status = stores.fkChoice[].on_attestation(
        stores.dag, step.att.data.slot, step.att.data.beacon_block_root,
        toSeq(stores.dag.get_attesting_indices(step.att.asTrusted)), time)
      doAssert status.isOk == step.valid
    of opOnBlock:
      withBlck(step.blck):
        let status = stepOnBlock(
          stores.dag, stores.fkChoice,
          verifier, state[], stateCache,
          blck, time, invalidatedRoots)
        doAssert status.isOk == step.valid
    of opOnAttesterSlashing:
      let indices =
        check_attester_slashing(state[], step.attesterSlashing, flags = {})
      if indices.isOk:
        for idx in indices.get:
          stores.fkChoice[].process_equivocation(idx)
      doAssert indices.isOk == step.valid
    of opInvalidateRoot:
      invalidatedRoots[step.invalidatedRoot] = step.latestValidHash
    of opChecks:
      stepChecks(step.checks, stores.dag, stores.fkChoice, time)
    else:
      doAssert false, "Unsupported"

proc runTest(testType: static[string], path: string, fork: ConsensusFork) =
  const SKIP = [
    # protoArray can handle blocks in the future gracefully
    # spec: https://github.com/ethereum/consensus-specs/blame/v1.1.3/specs/phase0/fork-choice.md#L349
    # test: tests/fork_choice/scenarios/no_votes.nim
    #       "Ensure the head is still 4 whilst the justified epoch is 0."
    "on_block_future_block",

    # TODO on_merge_block
    "too_early_for_merge",
    "too_late_for_merge",
    "block_lookup_failed",
    "all_valid",
  ]

  test testType & " - " & path.relativePath(SszTestsDir):
    when defined(windows):
      # Some test files have very long paths
      skip()
    else:
      if os_ops.splitPath(path).tail in SKIP:
        skip()
      else:
        doRunTest(path, fork)

template fcSuite(suiteName: static[string], testPathElem: static[string]) =
  suite "EF - " & suiteName & preset():
    const presetPath = SszTestsDir/const_preset
    for kind, path in walkDir(presetPath, relative = true, checkDir = true):
      let testsPath = presetPath/path/testPathElem
      if kind != pcDir or not os_ops.dirExists(testsPath):
        continue
      let fork = forkForPathComponent(path).valueOr:
        raiseAssert "Unknown test fork: " & testsPath
      for kind, path in walkDir(testsPath, relative = true, checkDir = true):
        let basePath = testsPath/path/"pyspec_tests"
        if kind != pcDir:
          continue
        for kind, path in walkDir(basePath, relative = true, checkDir = true):
          runTest(suiteName, basePath/path, fork)

fcSuite("ForkChoice", "fork_choice")
fcSuite("Sync", "sync")
