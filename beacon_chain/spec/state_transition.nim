# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition, as described in
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
#
# The entry point is `state_transition` which is at the bottom of the file!
#
# General notes about the code:
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * When updating the code, add TODO sections to mark where there are clear
#   improvements to be made - other than that, keep things similar to spec unless
#   motivated by security or performance considerations
#
# Performance notes:
# * The state transition is used in two contexts: to verify that incoming blocks
#   are correct and to replay existing blocks from database. Incoming blocks
#   are processed one-by-one while replay happens multiple blocks at a time.
# * Although signature verification is the slowest operation in the state
#   state transition, we skip it during replay - this is also when we repeatedly
#   call the state transition, making the non-signature part of the code
#   important from a performance point of view.
# * It's important to start with a prefilled cache - generating the shuffled
#   list of active validators is generally very slow.
# * Throughout, the code is affected by inefficient for loop codegen, meaning
#   that we have to iterate over indices and pick out the value manually:
#   https://github.com/nim-lang/Nim/issues/14421
# * Throughout, we're affected by inefficient `let` borrowing, meaning we
#   often have to take the address of a sequence item due to the above - look
#   for `let ... = unsafeAddr sequence[idx]`
# * Throughout, we're affected by the overloading rules that prefer a `var`
#   overload to a non-var overload - look for `asSeq()` - when the `var`
#   overload is used, the hash tree cache is cleared, which, aside from being
#   slow itself, causes additional processing to recalculate the Merkle tree.

{.push raises: [].}

import
  chronicles,
  stew/results,
  ../extras,
  "."/[
    beaconstate, eth2_merkleization, forks, helpers, signatures,
    state_transition_block, state_transition_epoch, validator]

export results, extras

logScope:
  topics = "state_transition"

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc verify_block_signature(
    state: ForkyBeaconState, signed_block: SomeForkySignedBeaconBlock):
    Result[void, cstring] =
  let
    proposer_index = signed_block.message.proposer_index
  if proposer_index >= state.validators.lenu64:
   return err("block: invalid proposer index")

  if not verify_block_signature(
      state.fork, state.genesis_validators_root, signed_block.message.slot,
      signed_block.root, state.validators[proposer_index].pubkey,
      signed_block.signature):
    return err("block: signature verification failed")

  ok()

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
func verifyStateRoot(
    state: ForkyBeaconState,
    blck: ForkyBeaconBlock | ForkySigVerifiedBeaconBlock):
    Result[void, cstring] =
  # This is inlined in state_transition(...) in spec.
  let state_root = hash_tree_root(state)
  if state_root != blck.state_root:
    err("block: state root verification failed")
  else:
    ok()

func verifyStateRoot(
    state: ForkyBeaconState, blck: ForkyTrustedBeaconBlock):
    Result[void, cstring] =
  # This is inlined in state_transition(...) in spec.
  ok()

type
  RollbackProc* = proc() {.gcsafe, noSideEffect, raises: [].}
  RollbackHashedProc*[T] =
    proc(state: var T) {.gcsafe, noSideEffect, raises: [].}
  RollbackForkedHashedProc* = RollbackHashedProc[ForkedHashedBeaconState]

func noRollback*() =
  trace "Skipping rollback of broken state"

# Hashed-state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.3/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
func process_slot*(
    state: var ForkyBeaconState, pre_state_root: Eth2Digest) =
  # `process_slot` is the first stage of per-slot processing - it is run for
  # every slot, including epoch slots - it does not however update the slot
  # number! `pre_state_root` refers to the state root of the incoming
  # state before any slot processing has been done.

  # Cache state root
  state.state_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] = pre_state_root

  # Cache latest block header state root
  if state.latest_block_header.state_root == ZERO_HASH:
    state.latest_block_header.state_root = pre_state_root

  # Cache block root
  state.block_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    hash_tree_root(state.latest_block_header)

func clear_epoch_from_cache(cache: var StateCache, epoch: Epoch) =
  cache.total_active_balance.del epoch
  cache.shuffled_active_validator_indices.del epoch

  for slot in epoch.slots():
    cache.beacon_proposer_indices.del slot

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc advance_slot(
    cfg: RuntimeConfig,
    state: var ForkyBeaconState, previous_slot_state_root: Eth2Digest,
    flags: UpdateFlags, cache: var StateCache, info: var ForkyEpochInfo):
    Result[void, cstring] =
  # Do the per-slot and potentially the per-epoch processing, then bump the
  # slot number - we've now arrived at the slot state on top of which a block
  # optionally can be applied.
  process_slot(state, previous_slot_state_root)

  info.clear()

  # Process epoch on the start slot of the next epoch
  let is_epoch_transition = (state.slot + 1).is_epoch
  if is_epoch_transition:
    # Note: Genesis epoch = 0, no need to test if before Genesis
    ? process_epoch(cfg, state, flags, cache, info)
    clear_epoch_from_cache(cache, (state.slot + 1).epoch)

  state.slot += 1

  ok()

func noRollback*(state: var phase0.HashedBeaconState) =
  trace "Skipping rollback of broken phase 0 state"

func noRollback*(state: var altair.HashedBeaconState) =
  trace "Skipping rollback of broken Altair state"

func noRollback*(state: var bellatrix.HashedBeaconState) =
  trace "Skipping rollback of broken Bellatrix state"

from ./datatypes/capella import
  ExecutionPayload, HashedBeaconState, SignedBLSToExecutionChangeList,
  asSigVerified

func noRollback*(state: var capella.HashedBeaconState) =
  trace "Skipping rollback of broken Capella state"

from ./datatypes/deneb import HashedBeaconState

func noRollback*(state: var deneb.HashedBeaconState) =
  trace "Skipping rollback of broken Deneb state"

func maybeUpgradeStateToAltair(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.ALTAIR_FORK_EPOCH and
      state.kind == ConsensusFork.Phase0:
    let newState = upgrade_to_altair(cfg, state.phase0Data.data)
    state = (ref ForkedHashedBeaconState)(
      kind: ConsensusFork.Altair,
      altairData: altair.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeStateToBellatrix(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.BELLATRIX_FORK_EPOCH and
      state.kind == ConsensusFork.Altair:
    let newState = upgrade_to_bellatrix(cfg, state.altairData.data)
    state = (ref ForkedHashedBeaconState)(
      kind: ConsensusFork.Bellatrix,
      bellatrixData: bellatrix.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeStateToCapella(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.CAPELLA_FORK_EPOCH and
      state.kind == ConsensusFork.Bellatrix:
    let newState = upgrade_to_capella(cfg, state.bellatrixData.data)
    state = (ref ForkedHashedBeaconState)(
      kind: ConsensusFork.Capella,
      capellaData: capella.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeStateToDeneb(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.DENEB_FORK_EPOCH and
      state.kind == ConsensusFork.Capella:
    let newState = upgrade_to_deneb(cfg, state.capellaData.data)
    state = (ref ForkedHashedBeaconState)(
      kind: ConsensusFork.Deneb,
      denebData: deneb.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeState*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  cfg.maybeUpgradeStateToAltair(state)
  cfg.maybeUpgradeStateToBellatrix(state)
  cfg.maybeUpgradeStateToCapella(state)
  cfg.maybeUpgradeStateToDeneb(state)

proc process_slots*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState, slot: Slot,
    cache: var StateCache, info: var ForkedEpochInfo, flags: UpdateFlags):
    Result[void, cstring] =
  if not (getStateField(state, slot) < slot):
    if slotProcessed notin flags or getStateField(state, slot) != slot:
      return err("process_slots: cannot rewind state to past slot")

  # Update the state so its slot matches that of the block
  while getStateField(state, slot) < slot:
    withState(state):
      withEpochInfo(forkyState.data, info):
        ? advance_slot(
          cfg, forkyState.data, forkyState.root, flags, cache, info)

      if skipLastStateRootCalculation notin flags or
          forkyState.data.slot < slot:
        # Don't update state root for the slot of the block if going to process
        # block after
        forkyState.root = hash_tree_root(forkyState.data)

    maybeUpgradeState(cfg, state)

  ok()

proc state_transition_block_aux(
    cfg: RuntimeConfig,
    state: var ForkyHashedBeaconState,
    signedBlock: SomeForkySignedBeaconBlock,
    cache: var StateCache, flags: UpdateFlags): Result[void, cstring] =
  # Block updates - these happen when there's a new block being suggested
  # by the block proposer. Every actor in the network will update its state
  # according to the contents of this block - but first they will validate
  # that the block is sane.
  if skipBlsValidation notin flags:
    ? verify_block_signature(state.data, signedBlock)

  trace "state_transition: processing block, signature passed",
    signature = shortLog(signedBlock.signature),
    blockRoot = shortLog(signedBlock.root)

  ? process_block(cfg, state.data, signedBlock.message, flags, cache)

  if skipStateRootValidation notin flags:
    ? verifyStateRoot(state.data, signedBlock.message)

  # only blocks currently being produced have an empty state root - we use a
  # separate function for those
  doAssert not signedBlock.message.state_root.isZero,
    "see makeBeaconBlock for block production"
  state.root = signedBlock.message.state_root

  ok()

func noRollback*(state: var ForkedHashedBeaconState) =
  trace "Skipping rollback of broken state"

proc state_transition_block*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    signedBlock: SomeForkySignedBeaconBlock,
    cache: var StateCache, flags: UpdateFlags,
    rollback: RollbackForkedHashedProc): Result[void, cstring] =
  ## `rollback` is called if the transition fails and the given state has been
  ## partially changed. If a temporary state was given to `state_transition`,
  ## it is safe to use `noRollback` and leave it broken, else the state
  ## object should be rolled back to a consistent state. If the transition fails
  ## before the state has been updated, `rollback` will not be called.
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
    cache: var StateCache, info: var ForkedEpochInfo, flags: UpdateFlags,
    rollback: RollbackForkedHashedProc): Result[void, cstring] =
  ## Apply a block to the state, advancing the slot counter as necessary. The
  ## given state must be of a lower slot, or, in case the `slotProcessed` flag
  ## is set, can be the slot state of the same slot as the block (where the
  ## slot state is the state without any block applied). To create a slot state,
  ## advance the state corresponding to the the parent block using
  ## `process_slots`.
  ##
  ## To run the state transition function in preparation for block production,
  ## use `makeBeaconBlock` instead.
  ##
  ## `rollback` is called if the transition fails and the given state has been
  ## partially changed. If a temporary state was given to `state_transition`,
  ## it is safe to use `noRollback` and leave it broken, else the state
  ## object should be rolled back to a consistent state. If the transition fails
  ## before the state has been updated, `rollback` will not be called.
  ? process_slots(
      cfg, state, signedBlock.message.slot, cache, info,
      flags + {skipLastStateRootCalculation})

  state_transition_block(
    cfg, state, signedBlock, cache, flags, rollback)

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

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#preparing-for-a-beaconblock
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

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.1/specs/altair/validator.md#preparing-a-beaconblock
  when consensusFork >= ConsensusFork.Altair:
    res.body.sync_aggregate = sync_aggregate

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/bellatrix/validator.md#block-proposal
  when consensusFork >= ConsensusFork.Bellatrix:
    res.body.execution_payload = execution_payload.executionPayload

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/validator.md#block-proposal
  when consensusFork >= ConsensusFork.Capella:
    res.body.bls_to_execution_changes =
      validator_changes.bls_to_execution_changes

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/deneb/validator.md#constructing-the-beaconblockbody
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
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags,
    transactions_root: Opt[Eth2Digest],
    execution_payload_root: Opt[Eth2Digest],
    kzg_commitments: Opt[KzgCommitments]):
    Result[ForkedBeaconBlock, cstring] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  template makeBeaconBlock(kind: untyped): Result[ForkedBeaconBlock, cstring] =
    # To create a block, we'll first apply a partial block to the state, skipping
    # some validations.

    var blck =
      ForkedBeaconBlock.init(
        partialBeaconBlock(
          cfg, state.`kind Data`, proposer_index, randao_reveal, eth1_data,
          graffiti, attestations, deposits, validator_changes, sync_aggregate,
          executionPayload))

    let res = process_block(
      cfg, state.`kind Data`.data, blck.`kind Data`.asSigVerified(),
      verificationFlags, cache)
    if res.isErr:
      rollback(state)
      return err(res.error())

    # Override for Builder API
    if transactions_root.isSome and execution_payload_root.isSome:
      withState(state):
        when consensusFork < ConsensusFork.Capella:
          # Nimbus doesn't support pre-Capella builder API
          discard
        elif consensusFork == ConsensusFork.Capella:
          forkyState.data.latest_execution_payload_header.transactions_root =
            transactions_root.get

          # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/capella/beacon-chain.md#beaconblockbody
          # Effectively hash_tree_root(ExecutionPayload) with the beacon block
          # body, with the execution payload replaced by the execution payload
          # header. htr(payload) == htr(payload header), so substitute.
          forkyState.data.latest_block_header.body_root = hash_tree_root(
            [hash_tree_root(randao_reveal),
             hash_tree_root(eth1_data),
             hash_tree_root(graffiti),
             hash_tree_root(validator_changes.proposer_slashings),
             hash_tree_root(validator_changes.attester_slashings),
             hash_tree_root(List[Attestation, Limit MAX_ATTESTATIONS](attestations)),
             hash_tree_root(List[Deposit, Limit MAX_DEPOSITS](deposits)),
             hash_tree_root(validator_changes.voluntary_exits),
             hash_tree_root(sync_aggregate),
             execution_payload_root.get,
             hash_tree_root(validator_changes.bls_to_execution_changes)])
        elif consensusFork == ConsensusFork.Deneb:
          forkyState.data.latest_execution_payload_header.transactions_root =
            transactions_root.get

          when executionPayload is deneb.ExecutionPayloadForSigning:
            # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.4/specs/deneb/beacon-chain.md#beaconblockbody
            forkyState.data.latest_block_header.body_root = hash_tree_root(
              [hash_tree_root(randao_reveal),
               hash_tree_root(eth1_data),
               hash_tree_root(graffiti),
               hash_tree_root(validator_changes.proposer_slashings),
               hash_tree_root(validator_changes.attester_slashings),
               hash_tree_root(List[Attestation, Limit MAX_ATTESTATIONS](attestations)),
               hash_tree_root(List[Deposit, Limit MAX_DEPOSITS](deposits)),
               hash_tree_root(validator_changes.voluntary_exits),
               hash_tree_root(sync_aggregate),
               execution_payload_root.get,
               hash_tree_root(validator_changes.bls_to_execution_changes),
               hash_tree_root(kzg_commitments.get)
            ])
          else:
            raiseAssert "Attempt to use non-Deneb payload with post-Deneb state"
        else:
          static: raiseAssert "Unreachable"


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

proc makeBeaconBlock*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState,
    proposer_index: ValidatorIndex, randao_reveal: ValidatorSig,
    eth1_data: Eth1Data, graffiti: GraffitiBytes,
    attestations: seq[Attestation], deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    executionPayload: ForkyExecutionPayloadForSigning,
    rollback: RollbackForkedHashedProc,
    cache: var StateCache, verificationFlags: UpdateFlags):
    Result[ForkedBeaconBlock, cstring] =
  makeBeaconBlock(
    cfg, state, proposer_index, randao_reveal, eth1_data, graffiti,
    attestations, deposits, validator_changes, sync_aggregate,
    executionPayload, rollback, cache,
    verificationFlags = verificationFlags,
    transactions_root = Opt.none Eth2Digest,
    execution_payload_root = Opt.none Eth2Digest,
    kzg_commitments = Opt.none KzgCommitments)
