# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  # Status libraries
  chronicles,
  taskpools,
  # Internals
  ../../beacon_chain/spec/forks,
  ../../beacon_chain/fork_choice/[fork_choice, fork_choice_types],
  ../../beacon_chain/beacon_chain_db,
  ../../beacon_chain/consensus_object_pools/[
    blockchain_dag, block_clearance, block_quarantine, spec_cache],
  # Third-party
  yaml/tojson,
  # Test
  ../testutil, ../testdbutil,
  ./fixtures_utils, ./os_ops

from std/json import
  JsonNode, getBool, getInt, getStr, hasKey, items, len, pairs, `$`, `[]`
from std/sequtils import mapIt, toSeq
from std/strutils import contains, rsplit
from stew/byteutils import fromHex
from ../testbcutil import addHeadBlock
from ../../beacon_chain/spec/peerdas_helpers import
  verify_data_column_sidecar_inclusion_proof,
  verify_data_column_sidecar_kzg_proofs
from ../../beacon_chain/spec/state_transition_block import
  check_attester_slashing, validate_blobs

block:
  template sourceDir: string = currentSourcePath.rsplit(io2.DirSep, 1)[0]
  doAssert loadTrustedSetup(
    sourceDir &
      "/../../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt", 0).isOk

# Test format described at https://github.com/ethereum/consensus-specs/tree/v1.3.0/tests/formats/fork_choice
# Note that our implementation has been optimized with "ProtoArray"
# instead of following the spec (in particular the "store").

type
  OpKind = enum
    opOnTick
    opOnPhase0Attestation
    opOnElectraAttestation
    opOnBlock
    opOnMergeBlock
    opOnPhase0AttesterSlashing
    opOnElectraAttesterSlashing
    opInvalidateHash
    opChecks

  BlobData = object
    blobs: seq[KzgBlob]
    proofs: seq[KzgProof]

  Operation = object
    valid: bool
    # variant specific fields
    case kind: OpKind
    of opOnTick:
      tick: int
    of opOnPhase0Attestation:
      phase0Att: phase0.Attestation
    of opOnElectraAttestation:
      electraAtt: electra.Attestation
    of opOnBlock:
      blck: ForkedSignedBeaconBlock
      blobData: Opt[BlobData]
      columnsValid: bool
    of opOnMergeBlock:
      powBlock: PowBlock
    of opOnPhase0AttesterSlashing:
      phase0AttesterSlashing: phase0.AttesterSlashing
    of opOnElectraAttesterSlashing:
      electraAttesterSlashing: electra.AttesterSlashing
    of opInvalidateHash:
      invalidatedHash: Eth2Digest
      latestValidHash: Eth2Digest
    of opChecks:
      checks: JsonNode

proc initialLoad(
    path: string, db: BeaconChainDB,
    StateType, BlockType: typedesc
): tuple[dag: ChainDAGRef, fkChoice: ref ForkChoice] =
  let
    forkedState = loadForkedState(
      path/"anchor_state.ssz_snappy",
      StateType.kind)

  ChainDAGRef.preInit(db, forkedState[])

  let
    cfg = forkedState[].kind.genesisTestRuntimeConfig
    validatorMonitor = newClone(ValidatorMonitor.init(cfg))
    dag = ChainDAGRef.init(cfg, db, validatorMonitor, {})
    fkChoice = newClone(ForkChoice.init(
      cfg.CONFIRMATION_BYZANTINE_THRESHOLD,
      dag.getFinalizedEpochRef(), dag.finalizedHead.blck))

  (dag, fkChoice)

proc loadOps(
    path: string,
    fork: ConsensusFork
): seq[Operation] {.raises: [KeyError, ValueError].} =
  let stepsYAML = os_ops.readFile(path/"steps.yaml")
  let steps = loadToJson(stepsYAML)

  result = @[]
  for step in steps[0]:
    var numExtraFields = 0

    if step.hasKey"tick":
      result.add Operation(kind: opOnTick,
        tick: step["tick"].getInt())
    elif step.hasKey"attestation":
      let filename = step["attestation"].getStr()
      if fork >= ConsensusFork.Electra:
        result.add Operation(
          kind: opOnElectraAttestation, electraAtt: parseTest(
            path/filename & ".ssz_snappy", SSZ, electra.Attestation))
      else:
        result.add Operation(kind: opOnPhase0Attestation, phase0Att: parseTest(
          path/filename & ".ssz_snappy", SSZ, phase0.Attestation))
    elif step.hasKey"block":
      let filename = step["block"].getStr()
      doAssert step.hasKey"blobs" == step.hasKey"proofs"
      withConsensusFork(fork):
        let
          blck = loadBlock(path/filename & ".ssz_snappy", consensusFork)
          blobData =
            when consensusFork in [ConsensusFork.Deneb, ConsensusFork.Electra]:
              doAssert not step.hasKey"columns"
              if step.hasKey"blobs":
                numExtraFields += 2
                Opt.some BlobData(
                  blobs: distinctBase(parseTest(
                    path/(step["blobs"].getStr()) & ".ssz_snappy",
                    SSZ, List[KzgBlob, Limit MAX_BLOB_COMMITMENTS_PER_BLOCK])),
                  proofs: step["proofs"].mapIt(
                    KzgProof(bytes: fromHex(array[48, byte], it.getStr()))))
              else:
                Opt.none(BlobData)
            else:
              doAssert not step.hasKey"blobs"
              Opt.none(BlobData)

        var columnsValid = true
        when consensusFork >= ConsensusFork.Fulu:
          doAssert not step.hasKey"blobs"
          if step.hasKey"columns":
            numExtraFields += 1
            if step["columns"].len < 64:
              columnsValid = false
            for column_name in step["columns"]:
              let column = parseTest(
                path/(column_name.getStr()) & ".ssz_snappy", SSZ,
                fulu.DataColumnSidecar)
              columnsValid = columnsValid and
                verify_data_column_sidecar_inclusion_proof(column).isOk and
                verify_data_column_sidecar_kzg_proofs(column).isOk
              if not columnsValid:
                break
        else:
          doAssert not step.hasKey"columns"

        result.add Operation(kind: opOnBlock,
          blck: ForkedSignedBeaconBlock.init(blck),
          blobData: blobData,
          columnsValid: columnsValid)
    elif step.hasKey"attester_slashing":
      let filename = step["attester_slashing"].getStr()
      if fork >= ConsensusFork.Electra:
        result.add Operation(kind: opOnElectraAttesterSlashing,
          electraAttesterSlashing: parseTest(
            path/filename & ".ssz_snappy", SSZ, electra.AttesterSlashing))
      else:
        result.add Operation(kind: opOnPhase0AttesterSlashing,
          phase0AttesterSlashing: parseTest(
            path/filename & ".ssz_snappy", SSZ, phase0.AttesterSlashing))
    elif step.hasKey"payload_status":
      if step["payload_status"]["status"].getStr() == "INVALID":
        result.add Operation(kind: opInvalidateHash,
          valid: true,
          invalidatedHash: Eth2Digest.fromHex(step["block_hash"].getStr()),
          latestValidHash: Eth2Digest.fromHex(
            step["payload_status"]["latest_valid_hash"].getStr()))
    elif step.hasKey"checks":
      result.add Operation(kind: opChecks,
        checks: step["checks"])
    else:
      raiseAssert "Unknown test step: " & $step

    if step.hasKey"valid":
      doAssert step.len == 2 + numExtraFields
      result[^1].valid = step["valid"].getBool()
    elif not step.hasKey"checks" and not step.hasKey"payload_status":
      doAssert step.len == 1 + numExtraFields
      result[^1].valid = true

proc stepOnBlock(
       dag: ChainDAGRef,
       fkChoice: ref ForkChoice,
       verifier: var BatchVerifier,
       state: var ForkedHashedBeaconState,
       stateCache: var StateCache,
       signedBlock: ForkySignedBeaconBlock,
       blobData: Opt[BlobData],
       columnsValid: bool,
       time: BeaconTime,
       invalidatedHashes: Table[Eth2Digest, Eth2Digest]):
       Result[BlockRef, VerifierError] =
  # 1. Validate blobs and columns
  when typeof(signedBlock).kind in [ConsensusFork.Deneb, ConsensusFork.Electra]:
    let kzgCommits = signedBlock.message.body.blob_kzg_commitments.asSeq
    if kzgCommits.len > 0 or blobData.isSome:
      if blobData.isNone or kzgCommits.validate_blobs(
          blobData.get.blobs, blobData.get.proofs).isErr:
        return err(VerifierError.Invalid)
  else:
    doAssert blobData.isNone, "Pre-Deneb test with specified blob data"

  if not columnsValid:
    return err(VerifierError.Invalid)

  # 2. Move state to proper slot
  doAssert dag.updateState(
    state,
    dag.getBlockIdAtSlot(time.slotOrZero(dag.timeParams))
      .expect("block exists"),
    save = false,
    stateCache,
    dag.updateFlags
  )

  # 3. Add block to DAG
  const consensusFork = typeof(signedBlock).kind

  # In normal Nimbus flow, for this (effectively) newPayload-based INVALID, it
  # is checked even before entering the DAG, by the block processor. Currently
  # the optimistic sync test(s) don't include a later-fcU-INVALID case. Whilst
  # this wouldn't be part of this check, presumably, their FC test vector step
  # would also have `true` validity because it'd not be known they weren't, so
  # adding this mock of the block processor is realistic and sufficient.
  when consensusFork >= ConsensusFork.Bellatrix and consensusFork != ConsensusFork.Gloas:
    debugGloasComment "skip execution payload for Gloas?"
    let executionBlockHash =
      signedBlock.message.body.execution_payload.block_hash
    if executionBlockHash in invalidatedHashes:
      # Mocks fork choice INVALID list application. These tests sequence this
      # in a way the block processor does not, specifying each payload_status
      # before the block itself, while Nimbus fork choice treats invalidating
      # a non-existent block root as a no-op and does not remember it for the
      # future.
      let lvh = invalidatedHashes.getOrDefault(
        executionBlockHash, static(default(Eth2Digest)))
      fkChoice[].mark_root_invalid(dag.getEarliestInvalidBlockRoot(
        signedBlock.message.parent_root, lvh, executionBlockHash))

      return err VerifierError.Invalid

  let blockAdded = dag.addHeadBlock(verifier, signedBlock) do (
      blckRef: BlockRef, signedBlock: consensusFork.TrustedSignedBeaconBlock,
      state: consensusFork.BeaconState,
      epochRef: EpochRef, unrealized: FinalityCheckpoints):

    # 4. Update fork choice if valid
    let status = fkChoice[].process_block(
      dag, epochRef, blckRef, unrealized, signedBlock.message, time)
    doAssert status.isOk()

    # 5. Update DAG with new head
    var quarantine = Quarantine.init(dag.cfg)
    let
      newHeadRoot = fkChoice[].get_head(dag, time).get()
      newHead = dag.getBlockRef(newHeadRoot).get()
    discard fkChoice[].will_select_head(dag, newHead, time)
    dag.updateHead(newHead, quarantine, [])
    if dag.needStateCachesAndForkChoicePruning():
      dag.pruneStateCachesDAG()
      let pruneRes = fkChoice[].prune()
      doAssert pruneRes.isOk()

  blockAdded

proc stepChecks(
    checks: JsonNode,
    dag: ChainDAGRef,
    fkChoice: ref ForkChoice,
    time: BeaconTime) {.raises: [KeyError].} =
  doAssert checks.len >= 1, "No checks found"
  for check, val in checks:
    if check == "time":
      doAssert time.ns_since_genesis == val.getInt().seconds.nanoseconds()
      let slot = fkChoice.checkpoints.time.slotOrZero(dag.timeParams)
      doAssert slot == time.slotOrZero(dag.timeParams)
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
    elif check == "finalized_checkpoint":
      let checkpointRoot = fkChoice.checkpoints.finalized.root
      let checkpointEpoch = fkChoice.checkpoints.finalized.epoch
      doAssert checkpointEpoch == Epoch(val["epoch"].getInt())
      doAssert checkpointRoot == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "proposer_boost_root":
      doAssert fkChoice.checkpoints.proposer_boost_root ==
        Eth2Digest.fromHex(val.getStr())
    elif check == "genesis_time":
      # We do not store genesis in fork choice..
      discard
    else:
      raiseAssert "Unsupported check '" & $check & "'"

proc doRunTest(
    path: string, fork: ConsensusFork) {.raises: [KeyError, ValueError].} =
  let db = withConsensusFork(fork):
    BeaconChainDB.new(
      "", consensusFork.genesisTestRuntimeConfig, inMemory = true)
  defer:
    db.close()

  let
    stores = withConsensusFork(fork):
      initialLoad(
        path, db, consensusFork.BeaconState, consensusFork.BeaconBlock)

    rng = HmacDrbgContext.new()
    taskpool =
      try:
        Taskpool.new()
      except Exception as exc:
        fatal "Failed to initialize Taskpool", exc = exc.msg
        fail()
        return
  var verifier = BatchVerifier.init(rng, taskpool)

  let steps = loadOps(path, fork)
  var time = stores.fkChoice.checkpoints.time
  var invalidatedHashes: Table[Eth2Digest, Eth2Digest]

  let state = newClone(stores.dag.headState)
  var stateCache = StateCache()

  for step in steps:
    case step.kind
    of opOnTick:
      time = BeaconTime(ns_since_genesis: step.tick.seconds.nanoseconds)
      let status = stores.fkChoice[].update_time(stores.dag, time)
      doAssert status.isOk == step.valid
    of opOnPhase0Attestation:
      let status = stores.fkChoice[].on_attestation(
        stores.dag, step.phase0Att.data.slot, step.phase0Att.data.beacon_block_root,
        toSeq(stores.dag.get_attesting_indices(step.phase0Att.asTrusted)), time)
      doAssert status.isOk == step.valid
    of opOnElectraAttestation:
      let status = stores.fkChoice[].on_attestation(
        stores.dag, step.electraAtt.data.slot,
        step.electraAtt.data.beacon_block_root,
        toSeq(stores.dag.get_attesting_indices(step.electraAtt)), time)
      doAssert status.isOk == step.valid
    of opOnBlock:
      withBlck(step.blck):
        let status = stepOnBlock(
          stores.dag, stores.fkChoice,
          verifier, state[], stateCache,
          forkyBlck, step.blobData, step.columnsValid, time, invalidatedHashes)
        doAssert status.isOk == step.valid
    of opOnPhase0AttesterSlashing:
      let indices = check_attester_slashing(
        state[], step.phase0AttesterSlashing, flags = {})
      if indices.isOk:
        for idx in indices.get:
          stores.fkChoice[].process_equivocation(idx)
      doAssert indices.isOk == step.valid
    of opOnElectraAttesterSlashing:
      let indices = check_attester_slashing(
        state[], step.electraAttesterSlashing, flags = {})
      if indices.isOk:
        for idx in indices.get:
          stores.fkChoice[].process_equivocation(idx)
      doAssert indices.isOk == step.valid
    of opInvalidateHash:
      invalidatedHashes[step.invalidatedHash] = step.latestValidHash
    of opChecks:
      stepChecks(step.checks, stores.dag, stores.fkChoice, time)
    else:
      raiseAssert "Unsupported"

proc runTest(suiteName: static[string], path: string, fork: ConsensusFork) =
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

    # TODO intentional reorgs
    "should_override_forkchoice_update__false",
    "should_override_forkchoice_update__true",
    "basic_is_parent_root",
    "basic_is_head_root",
  ]

  test suiteName & " - " & path.relativeTestPathComponent():
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
      if path.contains("eip7732") or path.contains("eip7805") or path.contains("gloas"):
        continue
      let fork = forkForPathComponent(path).valueOr:
        raiseAssert "Unknown test fork: " & testsPath
      for kind, path in walkDir(testsPath, relative = true, checkDir = true):
        let basePath = testsPath/path/"pyspec_tests"
        if kind != pcDir:
          continue
        for kind, path in walkDir(basePath, relative = true, checkDir = true):
          # TODO https://github.com/ethereum/consensus-specs/pull/4807 modifies
          # proposer boost mechanics to depend on the canonical chain
          if  path.contains("voting_source_beyond_two_epoch") or
              path.contains("justified_update_not_realized_finality") or
              path.contains("justified_update_always_if_better"):
            continue
          runTest(suiteName, basePath/path, fork)

fcSuite("ForkChoice", "fork_choice")
fcSuite("Sync", "sync")
