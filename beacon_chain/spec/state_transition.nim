# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition, as described in
# https://github.com/ethereum/consensus-specs/blob/v1.1.8/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
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
#   slow itself, causes additional processing to recalculate the merkle tree.

{.push raises: [Defect].}

import
  std/tables,
  chronicles,
  stew/results,
  metrics,
  ../extras,
  ./datatypes/[phase0, altair, bellatrix],
  "."/[
    beaconstate, eth2_merkleization, forks, helpers, signatures,
    state_transition_block, state_transition_epoch, validator]

export extras, phase0, altair

type Foo = phase0.SignedBeaconBlock | altair.SignedBeaconBlock | phase0.TrustedSignedBeaconBlock | altair.TrustedSignedBeaconBlock | phase0.SigVerifiedSignedBeaconBlock | altair.SigVerifiedSignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock | bellatrix.SigVerifiedSignedBeaconBlock | bellatrix.SignedBeaconBlock

# https://github.com/ethereum/consensus-specs/blob/v1.1.8/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc verify_block_signature(
    #state: ForkyBeaconState, signed_block: SomeSomeSignedBeaconBlock): bool =
    state: ForkyBeaconState, signed_block: Foo): bool =
    #state: ForkyBeaconState, signed_block: phase0.SomeSignedBeaconBlock | altair.SomeSignedBeaconBlock): bool =
  let
    proposer_index = signed_block.message.proposer_index
  if proposer_index >= state.validators.lenu64:
    notice "Invalid proposer index in block",
      blck = shortLog(signed_block.message)
    return false

  if not verify_block_signature(
      state.fork, state.genesis_validators_root, signed_block.message.slot,
      signed_block.root, state.validators[proposer_index].pubkey,
      signed_block.signature):
    notice "Block: signature verification failed",
      blck = shortLog(signedBlock)
    return false

  true

# https://github.com/ethereum/consensus-specs/blob/v1.1.8/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc verifyStateRoot(state: ForkyBeaconState, blck: phase0.BeaconBlock or phase0.SigVerifiedBeaconBlock or altair.BeaconBlock or altair.SigVerifiedBeaconBlock or bellatrix.BeaconBlock or bellatrix.SigVerifiedBeaconBlock or bellatrix.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  let state_root = hash_tree_root(state)
  if state_root != blck.state_root:
    notice "Block: root verification failed",
      block_state_root = shortLog(blck.state_root), state_root = shortLog(state_root)
    false
  else:
    true

func verifyStateRoot(state: phase0.BeaconState, blck: phase0.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

func verifyStateRoot(state: altair.BeaconState, blck: altair.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

func verifyStateRoot(state: bellatrix.BeaconState, blck: bellatrix.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

# one of these can happen on the fork block itself (it's a phase 0 block which
# creates an Altair state)
func verifyStateRoot(state: altair.BeaconState, blck: phase0.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

func verifyStateRoot(state: bellatrix.BeaconState, blck: phase0.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

func verifyStateRoot(state: bellatrix.BeaconState, blck: altair.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

func verifyStateRoot(state: phase0.BeaconState, blck: altair.TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

type
  RollbackProc* = proc() {.gcsafe, raises: [Defect].}

func noRollback*() =
  trace "Skipping rollback of broken state"

type
  RollbackHashedProc* =       proc(state: var phase0.HashedBeaconState)    {.gcsafe, raises: [Defect].}
  RollbackAltairHashedProc* = proc(state: var altair.HashedBeaconState)    {.gcsafe, raises: [Defect].}
  RollbackMergeHashedProc* =  proc(state: var bellatrix.HashedBeaconState) {.gcsafe, raises: [Defect].}

# Hashed-state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.1.8/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
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
  cache.shuffled_active_validator_indices.del epoch
  let
    start_slot = epoch.compute_start_slot_at_epoch
    end_slot = (epoch + 1).compute_start_slot_at_epoch

  for i in start_slot ..< end_slot:
    cache.beacon_proposer_indices.del i

# https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc advance_slot(
    cfg: RuntimeConfig,
    state: var ForkyBeaconState, previous_slot_state_root: Eth2Digest,
    flags: UpdateFlags, cache: var StateCache, info: var ForkyEpochInfo) =
  # Do the per-slot and potentially the per-epoch processing, then bump the
  # slot number - we've now arrived at the slot state on top of which a block
  # optionally can be applied.
  process_slot(state, previous_slot_state_root)

  info.clear()

  let is_epoch_transition = (state.slot + 1).isEpoch
  if is_epoch_transition:
    # Note: Genesis epoch = 0, no need to test if before Genesis
    process_epoch(cfg, state, flags, cache, info)
    clear_epoch_from_cache(cache, (state.slot + 1).compute_epoch_at_slot)

  state.slot += 1

func noRollback*(state: var phase0.HashedBeaconState) =
  trace "Skipping rollback of broken phase 0 state"

func noRollback*(state: var altair.HashedBeaconState) =
  trace "Skipping rollback of broken Altair state"

func noRollback*(state: var bellatrix.HashedBeaconState) =
  trace "Skipping rollback of broken Bellatrix state"

proc maybeUpgradeStateToAltair(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.ALTAIR_FORK_EPOCH and
      state.kind == BeaconStateFork.Phase0:
    var newState = upgrade_to_altair(cfg, state.phase0Data.data)
    state = (ref ForkedHashedBeaconState)(
      kind: BeaconStateFork.Altair,
      altairData: altair.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeStateToBellatrix(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.MERGE_FORK_EPOCH and
      state.kind == BeaconStateFork.Altair:
    var newState = upgrade_to_merge(cfg, state.altairData.data)
    state = (ref ForkedHashedBeaconState)(
      kind: BeaconStateFork.Bellatrix,
      mergeData: bellatrix.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

proc maybeUpgradeState*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  cfg.maybeUpgradeStateToAltair(state)
  cfg.maybeUpgradeStateToBellatrix(state)

proc process_slots*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState, slot: Slot,
    cache: var StateCache, info: var ForkedEpochInfo, flags: UpdateFlags): bool =
  if not (getStateField(state, slot) < slot):
    if slotProcessed notin flags or getStateField(state, slot) != slot:
      notice "Unusual request for a slot in the past",
        state_root = shortLog(getStateRoot(state)),
        current_slot = getStateField(state, slot),
        target_slot = slot
      return false

  # Update the state so its slot matches that of the block
  while getStateField(state, slot) < slot:
    withState(state):
      withEpochInfo(state.data, info):
        advance_slot(
          cfg, state.data, state.root, flags, cache, info)

      if skipLastStateRootCalculation notin flags or
          state.data.slot < slot:
        # Don't update state root for the slot of the block if going to process
        # block after
        state.root = hash_tree_root(state.data)

    maybeUpgradeState(cfg, state)

  true

proc state_transition_block_aux(
    cfg: RuntimeConfig,
    state: var ForkyHashedBeaconState,
    signedBlock: phase0.SignedBeaconBlock | phase0.SigVerifiedSignedBeaconBlock |
                 phase0.TrustedSignedBeaconBlock | altair.SignedBeaconBlock |
                 altair.SigVerifiedSignedBeaconBlock | altair.TrustedSignedBeaconBlock |
                 bellatrix.TrustedSignedBeaconBlock | bellatrix.SigVerifiedSignedBeaconBlock |
                 bellatrix.SignedBeaconBlock,
    cache: var StateCache, flags: UpdateFlags): bool =
  # Block updates - these happen when there's a new block being suggested
  # by the block proposer. Every actor in the network will update its state
  # according to the contents of this block - but first they will validate
  # that the block is sane.
  if not (skipBLSValidation in flags or
      verify_block_signature(state.data, signedBlock)):
    return false

  trace "state_transition: processing block, signature passed",
    signature = shortLog(signedBlock.signature),
    blockRoot = shortLog(signedBlock.root)

  let res = process_block(cfg, state.data, signedBlock.message, flags, cache)

  if not res.isOk():
    debug "state_transition: process_block failed",
      blck = shortLog(signedBlock.message),
      slot = state.data.slot,
      eth1_deposit_index = state.data.eth1_deposit_index,
      deposit_root = shortLog(state.data.eth1_data.deposit_root),
      error = res.error
    return false

  if not (skipStateRootValidation in flags or
        verifyStateRoot(state.data, signedBlock.message)):
    return false

  # only blocks currently being produced have an empty state root - we use a
  # separate function for those
  doAssert signedBlock.message.state_root != Eth2Digest(),
    "see makeBeaconBlock for block production"
  state.root = signedBlock.message.state_root

  true

type
  RollbackForkedHashedProc* =
    proc(state: var ForkedHashedBeaconState) {.gcsafe, raises: [Defect].}

func noRollback*(state: var ForkedHashedBeaconState) =
  trace "Skipping rollback of broken state"

proc state_transition_block*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    signedBlock: phase0.SignedBeaconBlock | phase0.SigVerifiedSignedBeaconBlock |
                 phase0.TrustedSignedBeaconBlock |
                 altair.SignedBeaconBlock | altair.SigVerifiedSignedBeaconBlock |
                 altair.TrustedSignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock |
                 bellatrix.SigVerifiedSignedBeaconBlock | bellatrix.SignedBeaconBlock,
    cache: var StateCache, flags: UpdateFlags,
    rollback: RollbackForkedHashedProc): bool =
  ## `rollback` is called if the transition fails and the given state has been
  ## partially changed. If a temporary state was given to `state_transition`,
  ## it is safe to use `noRollback` and leave it broken, else the state
  ## object should be rolled back to a consistent state. If the transition fails
  ## before the state has been updated, `rollback` will not be called.
  doAssert not rollback.isNil, "use noRollback if it's ok to mess up state"

  # Ensure state_transition_block()-only callers trigger this
  maybeUpgradeStateToAltair(cfg, state)

  let success = withState(state):
    state_transition_block_aux(cfg, state, signedBlock, cache, flags)

  if not success:
    rollback(state)
    return false

  true

proc state_transition*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    signedBlock: phase0.SignedBeaconBlock | phase0.SigVerifiedSignedBeaconBlock |
                 phase0.TrustedSignedBeaconBlock | altair.SignedBeaconBlock |
                 altair.TrustedSignedBeaconBlock | bellatrix.TrustedSignedBeaconBlock |
                 bellatrix.SignedBeaconBlock,
    cache: var StateCache, info: var ForkedEpochInfo, flags: UpdateFlags,
    rollback: RollbackForkedHashedProc): bool =
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
  if not process_slots(
      cfg, state, signedBlock.message.slot, cache, info,
      flags + {skipLastStateRootCalculation}):
    return false
  state_transition_block(
    cfg, state, signedBlock, cache, flags, rollback)

# https://github.com/ethereum/consensus-specs/blob/v1.1.8/specs/phase0/validator.md#preparing-for-a-beaconblock
template partialBeaconBlock(
    cfg: RuntimeConfig,
    state: var phase0.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockExits,
    sync_aggregate: SyncAggregate,
    executionPayload: ExecutionPayload): phase0.BeaconBlock =
  phase0.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root(),
    body: phase0.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: exits.proposer_slashings,
      attester_slashings: exits.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: exits.voluntary_exits))

proc makeBeaconBlock*(
    cfg: RuntimeConfig,
    state: var phase0.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockExits,
    sync_aggregate: SyncAggregate,
    executionPayload: ExecutionPayload,
    rollback: RollbackHashedProc,
    cache: var StateCache): Result[phase0.BeaconBlock, string] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  # To create a block, we'll first apply a partial block to the state, skipping
  # some validations.

  var blck = partialBeaconBlock(cfg, state, proposer_index,
                                randao_reveal, eth1_data, graffiti, attestations, deposits,
                                exits, sync_aggregate, executionPayload)

  let res = process_block(cfg, state.data, blck, {skipBlsValidation}, cache)

  if res.isErr:
    warn "Unable to apply new block to state",
      blck = shortLog(blck),
      slot = state.data.slot,
      eth1_deposit_index = state.data.eth1_deposit_index,
      deposit_root = shortLog(state.data.eth1_data.deposit_root),
      error = res.error
    rollback(state)
    return err("Unable to apply new block to state: " & $res.error())

  state.root = hash_tree_root(state.data)
  blck.state_root = state.root
  ok(blck)

# https://github.com/ethereum/consensus-specs/blob/v1.1.8/specs/altair/validator.md#preparing-a-beaconblock
template partialBeaconBlock(
    cfg: RuntimeConfig,
    state: var altair.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockExits,
    sync_aggregate: SyncAggregate,
    executionPayload: ExecutionPayload): altair.BeaconBlock =
  altair.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root(),
    body: altair.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: exits.proposer_slashings,
      attester_slashings: exits.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: exits.voluntary_exits,
      sync_aggregate: sync_aggregate))

proc makeBeaconBlock*(
    cfg: RuntimeConfig,
    state: var altair.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockExits,
    sync_aggregate: SyncAggregate,
    executionPayload: ExecutionPayload,
    rollback: RollbackAltairHashedProc,
    cache: var StateCache): Result[altair.BeaconBlock, string] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  # To create a block, we'll first apply a partial block to the state, skipping
  # some validations.

  var blck = partialBeaconBlock(cfg, state, proposer_index,
                                randao_reveal, eth1_data, graffiti, attestations, deposits,
                                exits, sync_aggregate, executionPayload)

  let res = process_block(cfg, state.data, blck, {skipBlsValidation}, cache)

  if res.isErr:
    warn "Unable to apply new block to state",
      blck = shortLog(blck),
      slot = state.data.slot,
      eth1_deposit_index = state.data.eth1_deposit_index,
      deposit_root = shortLog(state.data.eth1_data.deposit_root),
      error = res.error
    rollback(state)
    return err("Unable to apply new block to state: " & $res.error())

  state.root = hash_tree_root(state.data)
  blck.state_root = state.root
  ok(blck)

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/merge/validator.md#block-proposal
template partialBeaconBlock(
    cfg: RuntimeConfig,
    state: var bellatrix.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockExits,
    sync_aggregate: SyncAggregate,
    executionPayload: ExecutionPayload): bellatrix.BeaconBlock =
  bellatrix.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root(),
    body: bellatrix.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: exits.proposer_slashings,
      attester_slashings: exits.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: exits.voluntary_exits,
      sync_aggregate: sync_aggregate,
      execution_payload: executionPayload))

proc makeBeaconBlock*(
    cfg: RuntimeConfig,
    state: var bellatrix.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockExits,
    sync_aggregate: SyncAggregate,
    executionPayload: ExecutionPayload,
    rollback: RollbackMergeHashedProc,
    cache: var StateCache): Result[bellatrix.BeaconBlock, string] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  # To create a block, we'll first apply a partial block to the state, skipping
  # some validations.

  var blck = partialBeaconBlock(cfg, state, proposer_index,
                                randao_reveal, eth1_data, graffiti, attestations, deposits,
                                exits, sync_aggregate, executionPayload)

  let res = process_block(cfg, state.data, blck, {skipBlsValidation}, cache)

  if res.isErr:
    warn "Unable to apply new block to state",
      blck = shortLog(blck),
      slot = state.data.slot,
      eth1_deposit_index = state.data.eth1_deposit_index,
      deposit_root = shortLog(state.data.eth1_data.deposit_root),
      error = res.error
    rollback(state)
    return err("Unable to apply new block to state: " & $res.error())

  state.root = hash_tree_root(state.data)
  blck.state_root = state.root
  ok(blck)

proc makeBeaconBlock*(
    cfg: RuntimeConfig,
    state: var ForkedHashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    exits: BeaconBlockExits,
    sync_aggregate: SyncAggregate,
    executionPayload: ExecutionPayload,
    rollback: RollbackForkedHashedProc,
    cache: var StateCache): Result[ForkedBeaconBlock, string] =
  ## Create a block for the given state. The latest block applied to it will
  ## be used for the parent_root value, and the slot will be take from
  ## state.slot meaning process_slots must be called up to the slot for which
  ## the block is to be created.

  template makeBeaconBlock(kind: untyped): Result[ForkedBeaconBlock, string] =
    # To create a block, we'll first apply a partial block to the state, skipping
    # some validations.

    var blck =
      ForkedBeaconBlock.init(
        partialBeaconBlock(cfg, state.`kind Data`, proposer_index,
                           randao_reveal, eth1_data, graffiti, attestations, deposits,
                           exits, sync_aggregate, executionPayload))

    let res = process_block(cfg, state.`kind Data`.data, blck.`kind Data`,
                            {skipBlsValidation}, cache)

    if res.isErr:
      warn "Unable to apply new block to state",
        blck = shortLog(blck),
        slot = state.`kind Data`.data.slot,
        eth1_deposit_index = state.`kind Data`.data.eth1_deposit_index,
        deposit_root = shortLog(state.`kind Data`.data.eth1_data.deposit_root),
        error = res.error
      rollback(state)
      return err("Unable to apply new block to state: " & $res.error())

    state.`kind Data`.root = hash_tree_root(state.`kind Data`.data)
    blck.`kind Data`.state_root = state.`kind Data`.root
    ok(blck)

  case state.kind
  of BeaconStateFork.Phase0:    makeBeaconBlock(phase0)
  of BeaconStateFork.Altair:    makeBeaconBlock(altair)
  of BeaconStateFork.Bellatrix: makeBeaconBlock(merge)
