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
  JsonNode, JsonNodeKind, getBool, getInt, getStr, hasKey, items, len, pairs,
  `$`, `[]`
from std/sequtils import mapIt, toSeq
from std/strutils import contains, rsplit
from stew/byteutils import fromHex
from ../testbcutil import addHeadBlock
from ../../beacon_chain/spec/peerdas_helpers import
  verify_data_column_sidecar_inclusion_proof,
  verify_data_column_sidecar_kzg_proofs
from ../../beacon_chain/spec/state_transition_block import
  check_attester_slashing, validate_blobs
from ../../beacon_chain/spec/beaconstate import
  is_valid_indexed_payload_attestation

block:
  template sourceDir: string = currentSourcePath.rsplit(io2.DirSep, 1)[0]
  doAssert loadTrustedSetup(
    sourceDir &
      "/../../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt", 7).isOk

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
    opOnExecutionPayload
    opOnPayloadAttestation
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
    of opOnExecutionPayload:
      executionPayload: gloas.SignedExecutionPayloadEnvelope
    of opOnPayloadAttestation:
      payloadAttestation: gloas.PayloadAttestationMessage
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
    elif step.hasKey"execution_payload":
      let filename = step["execution_payload"].getStr()
      result.add Operation(kind: opOnExecutionPayload,
        executionPayload: parseTest(
          path/filename & ".ssz_snappy", SSZ,
          gloas.SignedExecutionPayloadEnvelope))
    elif step.hasKey"payload_attestation" or
         step.hasKey"payload_attestation_message":
      let filename =
        if step.hasKey"payload_attestation":
          step["payload_attestation"].getStr()
        else:
          step["payload_attestation_message"].getStr()
      result.add Operation(kind: opOnPayloadAttestation,
        payloadAttestation: parseTest(
          path/filename & ".ssz_snappy", SSZ,
          gloas.PayloadAttestationMessage))
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

proc updateHead(
    dag: ChainDAGRef, fkChoice: ref ForkChoice, time: BeaconTime,
    updateFastConfirm = false) =
  var quarantine = Quarantine.init(dag.cfg)
  let
    newHeadRoot = fkChoice[].get_head(dag, time).get()
    newHead = dag.getBlockRef(newHeadRoot).get()
  if updateFastConfirm:
    doAssert fkChoice[].will_select_head(dag, newHead, time).isOk
  dag.updateHead(newHead, quarantine, [])
  if dag.needStateCachesAndForkChoicePruning():
    dag.pruneStateCachesDAG()
    let pruneRes = fkChoice[].prune(dag)
    doAssert pruneRes.isOk()

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
    invalidatedHashes: Table[Eth2Digest, Eth2Digest]
): Result[BlockRef, VerifierError] =
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
  when consensusFork >= ConsensusFork.Bellatrix and
       consensusFork notin [ConsensusFork.Gloas, ConsensusFork.Heze]:
    debugGloasComment "skip execution payload for Gloas?"
    let executionBlockHash =
      signedBlock.message.body.execution_payload.block_hash
    if executionBlockHash in invalidatedHashes:
      # Mocks fork choice INVALID list application. These tests sequence this
      # in a way the block processor does not, specifying each payload_status
      # before the block itself, while Nimbus fork choice treats invalidating
      # a non-existent block root as a no-op and does not remember it for the
      # future.
      let lvh = invalidatedHashes.getOrDefault(executionBlockHash, ZERO_HASH)
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

    # Save every post-block state to the DB so that a later `addHeadExecutionPayload`
    # can `updateState` to it directly instead of replaying through blocks and
    # hitting not-yet-revealed envelopes.
    when consensusFork >= ConsensusFork.Gloas:
      withState(dag.clearanceState):
        dag.db.putState(forkyState)

    # 5. Update DAG with new head
    dag.updateHead(fkChoice, time)

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
      if val.hasKey("payload_status"):
        # PAYLOAD_STATUS_EMPTY=0, PAYLOAD_STATUS_FULL=1.
        # The head is FULL iff a verified (FULL) node exists for its root.
        let isFull = headRoot in fkChoice.backend.proto_array.fullBlockIndices
        doAssert (if isFull: 1 else: 0) == val["payload_status"].getInt()
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
    elif check == "previous_epoch_observed_justified_checkpoint":
      discard  # Not tracked
    elif check == "current_epoch_observed_justified_checkpoint":
      let cp = fkChoice.backend.current_epoch_observed_justified.checkpoint
      doAssert cp.epoch == Epoch(val["epoch"].getInt())
      doAssert cp.root == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "previous_epoch_greatest_unrealized_checkpoint":
      let cp = fkChoice.backend.previous_epoch_greatest_unrealized_checkpoint
      doAssert cp.epoch == Epoch(val["epoch"].getInt())
      doAssert cp.root == Eth2Digest.fromHex(val["root"].getStr())
    elif check == "previous_slot_head":
      doAssert fkChoice.backend.previous_slot_head ==
        Eth2Digest.fromHex(val.getStr())
    elif check == "current_slot_head":
      doAssert fkChoice.backend.current_slot_head ==
        Eth2Digest.fromHex(val.getStr())
    elif check == "confirmed_root":
      doAssert fkChoice.backend.confirmed.root ==
        Eth2Digest.fromHex(val.getStr())
    elif check == "payload_timeliness_vote" or
         check == "payload_data_availability_vote":
      # `votes` is ordered by PTC position; a `null` position cast no vote, so
      # its bit stays unset, same observable value as a recorded `false`.
      let tally = fkChoice.backend.ptc_votes.getOrDefault(
        Eth2Digest.fromHex(val["block_root"].getStr()))
      var i = 0
      for v in val["votes"].items:
        let expected = v.kind != JNull and v.getBool()
        if check == "payload_timeliness_vote":
          doAssert tally.present[i] == expected
        else:
          doAssert tally.available[i] == expected
        inc i
    else:
      raiseAssert "Unsupported check '" & $check & "'"

proc doRunTest(
    path: string, fork: ConsensusFork,
    verifier: var BatchVerifier) {.raises: [KeyError, ValueError].} =
  let db = withConsensusFork(fork):
    BeaconChainDB.new(
      "", consensusFork.genesisTestRuntimeConfig, inMemory = true)
  defer:
    db.close()

  let
    stores = withConsensusFork(fork):
      initialLoad(
        path, db, consensusFork.BeaconState, consensusFork.BeaconBlock)
    steps = loadOps(path, fork)
  var time = stores.fkChoice.checkpoints.time
  var invalidatedHashes: Table[Eth2Digest, Eth2Digest]
  # Keep the gloas signed blocks around so a later `execution_payload`
  # step can verify its envelope against the matching block via
  # `addHeadExecutionPayload`.
  var gloasBlocks: Table[Eth2Digest, ForkedSignedBeaconBlock]

  let state = newClone(stores.dag.headState)
  var stateCache = StateCache()

  for step in steps:
    case step.kind
    of opOnTick:
      time = BeaconTime(ns_since_genesis: step.tick.seconds.nanoseconds)
      let status = stores.fkChoice[].update_time(stores.dag, time)
      doAssert status.isOk == step.valid
      if status.isOk:
        stores.dag.updateHead(stores.fkChoice, time, updateFastConfirm = true)
    of opOnPhase0Attestation:
      let status = stores.fkChoice[].on_attestation(
        stores.dag, step.phase0Att.data.slot, step.phase0Att.data.beacon_block_root,
        toSeq(stores.dag.get_attesting_indices(step.phase0Att.asTrusted)),
        CommitteeIndex(step.phase0Att.data.index), time)
      doAssert status.isOk == step.valid
    of opOnElectraAttestation:
      let status = stores.fkChoice[].on_attestation(
        stores.dag, step.electraAtt.data.slot,
        step.electraAtt.data.beacon_block_root,
        toSeq(stores.dag.get_attesting_indices(step.electraAtt)),
        CommitteeIndex(step.electraAtt.data.index), time)
      doAssert status.isOk == step.valid
    of opOnBlock:
      withBlck(step.blck):
        let status = stepOnBlock(
          stores.dag, stores.fkChoice,
          verifier, state[], stateCache,
          forkyBlck, step.blobData, step.columnsValid, time, invalidatedHashes)
        doAssert status.isOk == step.valid
        when typeof(forkyBlck.message).kind >= ConsensusFork.Gloas:
          if status.isOk:
            gloasBlocks[forkyBlck.root] = step.blck
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
    of opOnExecutionPayload:
      let envBlockRoot = step.executionPayload.message.beacon_block_root
      var valid = false
      if envBlockRoot in gloasBlocks:
        withBlck(gloasBlocks[envBlockRoot]):
          when consensusFork == ConsensusFork.Gloas:
            let addRes = stores.dag.addHeadExecutionPayload(
              forkyBlck, step.executionPayload)
            if addRes.isOk:
              doAssert stores.fkChoice[].on_execution_payload(
                stores.dag.cfg, stores.dag.timeParams,
                step.executionPayload).isOk
            valid = addRes.isOk
      doAssert valid == step.valid
    of opOnPayloadAttestation:
      let pa = step.payloadAttestation
      # This suite has no gossip layer, so mirror the signature check gossip
      # does before recording.
      var valid = false
      withState(stores.dag.headState):
        when consensusFork >= ConsensusFork.Gloas:
          var attesting_indices: List[uint64, Limit PTC_SIZE]
          discard attesting_indices.add(pa.validator_index)
          if is_valid_indexed_payload_attestation(forkyState.data,
              IndexedPayloadAttestation(
                attesting_indices: attesting_indices,
                data: pa.data, signature: pa.signature)):
            valid = stores.fkChoice[].on_payload_attestation_message(
              stores.dag, pa.validator_index, pa.data).isOk
      doAssert valid == step.valid
    of opChecks:
      stepChecks(step.checks, stores.dag, stores.fkChoice, time)
    else:
      raiseAssert "Unsupported"

proc runTest(
    suiteName: static[string], path: string, fork: ConsensusFork,
    rng: ref HmacDrbgContext, taskpool: Taskpool) =
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
        var verifier = BatchVerifier.init(rng, taskpool)
        doRunTest(path, fork, verifier)

template fcSuite(suiteName: static[string], testPathElem: static[string]) =
  suite "EF - " & suiteName & preset():
    let
      rng = HmacDrbgContext.new()
      taskpool =
        try:
          Taskpool.new()
        except Exception as exc:
          raiseAssert "Failed to initialize Taskpool: " & exc.msg
    const presetPath = SszTestsDir/const_preset
    for kind, path in walkDir(presetPath, relative = true, checkDir = true):
      let testsPath = presetPath/path/testPathElem
      if kind != pcDir or not os_ops.dirExists(testsPath):
        continue
      if path.contains("heze"):
        continue
      let fork = forkForPathComponent(path).valueOr:
        raiseAssert "Unknown test fork: " & testsPath
      for kind, path in walkDir(testsPath, relative = true, checkDir = true):
        let basePath = testsPath/path/"pyspec_tests"
        if kind != pcDir:
          continue
        # The Gloas/ePBS fork-choice handlers wired so far cover the execution
        # payload envelope and PTC message categories; the remaining categories
        # depend on EMPTY/FULL head selection that is not yet wired here.
        if testsPath.contains("gloas") and path notin [
            "on_execution_payload_envelope", "on_payload_attestation_message"]:
          continue
        for kind, path in walkDir(basePath, relative = true, checkDir = true):
          runTest(suiteName, basePath/path, fork, rng, taskpool)

fcSuite("ForkChoice", "fork_choice")
fcSuite("Sync", "sync")
fcSuite("Fast Confirmation", "fast_confirmation")
