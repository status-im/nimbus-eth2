import
  results,
  "."/[
    beaconstate, eth2_merkleization, forks]

export results

type
  RollbackProc* = proc() {.gcsafe, noSideEffect, raises: [].}
  RollbackHashedProc*[T] =
    proc(state: var T) {.gcsafe, noSideEffect, raises: [].}
  RollbackForkedHashedProc* = RollbackHashedProc[ForkedHashedBeaconState]

func noRollback*() = discard

func process_slot*(
    state: var ForkyBeaconState, pre_state_root: Eth2Digest) =

  state.state_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] = pre_state_root

  if state.latest_block_header.state_root == ZERO_HASH:
    state.latest_block_header.state_root = pre_state_root

  state.block_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    hash_tree_root(state.latest_block_header)

proc advance_slot(
    cfg: RuntimeConfig,
    state: var ForkyBeaconState, previous_slot_state_root: Eth2Digest,
    cache: var StateCache, info: var ForkyEpochInfo):
    Result[void, cstring] =
  process_slot(state, previous_slot_state_root)

  info.clear()

  state.slot += 1

  ok()

func noRollback*(state: var phase0.HashedBeaconState) = discard
func noRollback*(state: var altair.HashedBeaconState) = discard
func noRollback*(state: var bellatrix.HashedBeaconState) = discard
func noRollback*(state: var capella.HashedBeaconState) = discard
func noRollback*(state: var deneb.HashedBeaconState) = discard
func noRollback*(state: var electra.HashedBeaconState) = discard

proc process_slots*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState, slot: Slot,
    cache: var StateCache, info: var ForkedEpochInfo):
    Result[void, cstring] =
  while getStateField(state, slot) < slot:
    withState(state):
      withEpochInfo(forkyState.data, info):
        ? advance_slot(
          cfg, forkyState.data, forkyState.root, cache, info)

      forkyState.root = hash_tree_root(forkyState.data)

  ok()

proc state_transition_block_aux(
    cfg: RuntimeConfig,
    state: var ForkyHashedBeaconState,
    signedBlock: SomeForkySignedBeaconBlock,
    cache: var StateCache): Result[void, cstring] =
  state.root = signedBlock.message.state_root

  ok()

func noRollback*(state: var ForkedHashedBeaconState) = discard

proc state_transition_block*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    signedBlock: SomeForkySignedBeaconBlock,
    cache: var StateCache,
    rollback: RollbackForkedHashedProc): Result[void, cstring] =
  doAssert not rollback.isNil, "use noRollback if it's ok to mess up state"

  let res = withState(state):
    when consensusFork == type(signedBlock).kind:
      state_transition_block_aux(cfg, forkyState, signedBlock, cache, flags)
    else:
      err("State/block fork mismatch")

  if res.isErr():
    rollback(state)

  res

proc state_transition*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    signedBlock: SomeForkySignedBeaconBlock,
    cache: var StateCache, info: var ForkedEpochInfo,
    rollback: RollbackForkedHashedProc): Result[void, cstring] =
  ? process_slots(
      cfg, state, signedBlock.message.slot, cache, info,
      flags + {skipLastStateRootCalculation})

  state_transition_block(
    cfg, state, signedBlock, cache, rollback)

func partialBeaconBlock*(
    cfg: RuntimeConfig,
    state: var ForkyHashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: ForkyExecutionPayloadForSigning
): auto =
  const consensusFork = typeof(state).kind

  var res = consensusFork.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root,
    body: consensusFork.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1_data,
      graffiti: graffiti,
      proposer_slashings: validator_changes.proposer_slashings,
      attester_slashings: validator_changes.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: validator_changes.voluntary_exits))

  when consensusFork >= ConsensusFork.Altair:
    res.body.sync_aggregate = sync_aggregate

  when consensusFork >= ConsensusFork.Bellatrix:
    res.body.execution_payload = execution_payload.executionPayload

  when consensusFork >= ConsensusFork.Capella:
    res.body.bls_to_execution_changes =
      validator_changes.bls_to_execution_changes

  when consensusFork >= ConsensusFork.Deneb:
    res.body.blob_kzg_commitments = execution_payload.blobsBundle.commitments

  res

proc makeBeaconBlock*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    executionPayload: ForkyExecutionPayloadForSigning,
    rollback: RollbackForkedHashedProc,
    cache: var StateCache,
    transactions_root: Opt[Eth2Digest],
    execution_payload_root: Opt[Eth2Digest],
    kzg_commitments: Opt[KzgCommitments]):
    Result[ForkedBeaconBlock, cstring] =
  template makeBeaconBlock(kind: untyped): Result[ForkedBeaconBlock, cstring] =

    var blck =
      ForkedBeaconBlock.init(
        partialBeaconBlock(
          cfg, state.`kind Data`, proposer_index, randao_reveal, eth1_data,
          graffiti, attestations, deposits, validator_changes, sync_aggregate,
          executionPayload))

    state.`kind Data`.root = hash_tree_root(state.`kind Data`.data)
    blck.`kind Data`.state_root = state.`kind Data`.root

    ok(blck)

  const payloadFork = typeof(executionPayload).kind
  when payloadFork == ConsensusFork.Bellatrix:
    case state.kind
    of ConsensusFork.Phase0:    makeBeaconBlock(phase0)
    of ConsensusFork.Altair:    makeBeaconBlock(altair)
    of ConsensusFork.Bellatrix: makeBeaconBlock(bellatrix)
    else: raiseAssert "Attempt to use Bellatrix payload with post-Bellatrix state"
  elif payloadFork == ConsensusFork.Capella:
    case state.kind
    of ConsensusFork.Capella:   makeBeaconBlock(capella)
    else: raiseAssert "Attempt to use Capella payload with non-Capella state"
  elif payloadFork == ConsensusFork.Deneb:
    case state.kind
    of ConsensusFork.Deneb:     makeBeaconBlock(deneb)
    else: raiseAssert "Attempt to use Deneb payload with non-Deneb state"
  elif payloadFork == ConsensusFork.Electra:
    case state.kind
    of ConsensusFork.Electra:     makeBeaconBlock(electra)
    else: raiseAssert "Attempt to use Electra payload with non-Electra state"
  else:
    {.error: "Unsupported fork".}

proc makeBeaconBlock*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState,
    proposer_index: ValidatorIndex, randao_reveal: ValidatorSig,
    eth1_data: Eth1Data, graffiti: GraffitiBytes,
    attestations: seq[Attestation], deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    executionPayload: ForkyExecutionPayloadForSigning,
    rollback: RollbackForkedHashedProc, cache: var StateCache):
    Result[ForkedBeaconBlock, cstring] =
  makeBeaconBlock(
    cfg, state, proposer_index, randao_reveal, eth1_data, graffiti,
    attestations, deposits, validator_changes, sync_aggregate,
    executionPayload, rollback, cache,
    verificationFlags = {}, transactions_root = Opt.none Eth2Digest,
    execution_payload_root = Opt.none Eth2Digest,
    kzg_commitments = Opt.none KzgCommitments)
