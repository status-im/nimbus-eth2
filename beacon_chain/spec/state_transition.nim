# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition, as described in
# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
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

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  chronicles,
  stew/results,
  ../extras,
  ./datatypes/[phase0, altair, bellatrix],
  "."/[
    beaconstate, eth2_merkleization, forks, helpers, signatures,
    state_transition_block, state_transition_epoch, validator]

export results, extras, phase0, altair, bellatrix

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
func verifyStateRoot(
    state: ForkyBeaconState, blck: ForkyBeaconBlock | ForkySigVerifiedBeaconBlock):
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
  RollbackProc* = proc() {.gcsafe, noSideEffect, raises: [Defect].}
  RollbackHashedProc*[T] =
    proc(state: var T) {.gcsafe, noSideEffect, raises: [Defect].}
  RollbackForkedHashedProc* = RollbackHashedProc[ForkedHashedBeaconState]

func noRollback*() =
  trace "Skipping rollback of broken state"

# Hashed-state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
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

from ./datatypes/eip4844 import HashedBeaconState

func noRollback*(state: var eip4844.HashedBeaconState) =
  trace "Skipping rollback of broken EIP4844 state"

func maybeUpgradeStateToAltair(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.ALTAIR_FORK_EPOCH and
      state.kind == BeaconStateFork.Phase0:
    let newState = upgrade_to_altair(cfg, state.phase0Data.data)
    state = (ref ForkedHashedBeaconState)(
      kind: BeaconStateFork.Altair,
      altairData: altair.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeStateToBellatrix(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.BELLATRIX_FORK_EPOCH and
      state.kind == BeaconStateFork.Altair:
    let newState = upgrade_to_bellatrix(cfg, state.altairData.data)
    state = (ref ForkedHashedBeaconState)(
      kind: BeaconStateFork.Bellatrix,
      bellatrixData: bellatrix.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeStateToCapella(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.CAPELLA_FORK_EPOCH and
      state.kind == BeaconStateFork.Bellatrix:
    let newState = upgrade_to_capella(cfg, state.bellatrixData.data)
    state = (ref ForkedHashedBeaconState)(
      kind: BeaconStateFork.Capella,
      capellaData: capella.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeStateToEIP4844(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  # Both process_slots() and state_transition_block() call this, so only run it
  # once by checking for existing fork.
  if getStateField(state, slot).epoch == cfg.EIP4844_FORK_EPOCH and
      state.kind == BeaconStateFork.Capella:
    let newState = upgrade_to_eip4844(cfg, state.capellaData.data)
    state = (ref ForkedHashedBeaconState)(
      kind: BeaconStateFork.EIP4844,
      eip4844Data: eip4844.HashedBeaconState(
        root: hash_tree_root(newState[]), data: newState[]))[]

func maybeUpgradeState*(
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState) =
  cfg.maybeUpgradeStateToAltair(state)
  cfg.maybeUpgradeStateToBellatrix(state)
  cfg.maybeUpgradeStateToCapella(state)
  cfg.maybeUpgradeStateToEIP4844(state)

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
    when stateFork.toBeaconBlockFork() == type(signedBlock).toFork:
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

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/phase0/validator.md#preparing-for-a-beaconblock
template partialBeaconBlock*(
    cfg: RuntimeConfig,
    state: var phase0.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: bellatrix.ExecutionPayload,
    bls_to_execution_changes: SignedBLSToExecutionChangeList):
    phase0.BeaconBlock =
  phase0.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root,
    body: phase0.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: validator_changes.proposer_slashings,
      attester_slashings: validator_changes.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: validator_changes.voluntary_exits))

# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/altair/validator.md#preparing-a-beaconblock
template partialBeaconBlock*(
    cfg: RuntimeConfig,
    state: var altair.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: bellatrix.ExecutionPayload,
    bls_to_execution_changes: SignedBLSToExecutionChangeList):  # TODO remove
    altair.BeaconBlock =
  altair.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root,
    body: altair.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: validator_changes.proposer_slashings,
      attester_slashings: validator_changes.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: validator_changes.voluntary_exits,
      sync_aggregate: sync_aggregate))

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/merge/validator.md#block-proposal
template partialBeaconBlock*(
    cfg: RuntimeConfig,
    state: var bellatrix.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: bellatrix.ExecutionPayload,
    bls_to_execution_changes: SignedBLSToExecutionChangeList):  # TODO remove
    bellatrix.BeaconBlock =
  bellatrix.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root,
    body: bellatrix.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: validator_changes.proposer_slashings,
      attester_slashings: validator_changes.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: validator_changes.voluntary_exits,
      sync_aggregate: sync_aggregate,
      execution_payload: execution_payload))

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/merge/validator.md#block-proposal
template partialBeaconBlock*(
    cfg: RuntimeConfig,
    state: var capella.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: capella.ExecutionPayload,
    bls_to_execution_changes: SignedBLSToExecutionChangeList   # TODO remove
    ):
    capella.BeaconBlock =
  capella.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root,
    body: capella.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: validator_changes.proposer_slashings,
      attester_slashings: validator_changes.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: validator_changes.voluntary_exits,
      sync_aggregate: sync_aggregate,
      execution_payload: execution_payload,
      bls_to_execution_changes: validator_changes.bls_to_execution_changes
      ))

# https://github.com/ethereum/consensus-specs/blob/v1.1.3/specs/merge/validator.md#block-proposal
template partialBeaconBlock*(
    cfg: RuntimeConfig,
    state: var eip4844.HashedBeaconState,
    proposer_index: ValidatorIndex,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    validator_changes: BeaconBlockValidatorChanges,
    sync_aggregate: SyncAggregate,
    execution_payload: eip4844.ExecutionPayload,
    bls_to_execution_changes: SignedBLSToExecutionChangeList   # TODO remove
    ):
    eip4844.BeaconBlock =
  discard $eip4844ImplementationMissing & ": state_transition.nim: partialBeaconBlock, leaves additional fields default, okay for block_sim"
  eip4844.BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: state.latest_block_root,
    body: eip4844.BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: validator_changes.proposer_slashings,
      attester_slashings: validator_changes.attester_slashings,
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits: validator_changes.voluntary_exits,
      sync_aggregate: sync_aggregate,
      execution_payload: execution_payload,
      bls_to_execution_changes: validator_changes.bls_to_execution_changes
      ))

proc makeBeaconBlock*[T: bellatrix.ExecutionPayload | capella.ExecutionPayload](
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
    executionPayload: T,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackForkedHashedProc,
    cache: var StateCache,
    # TODO:
    # `verificationFlags` is needed only in tests and can be
    # removed if we don't use invalid signatures there
    verificationFlags: UpdateFlags,
    transactions_root: Opt[Eth2Digest],
    execution_payload_root: Opt[Eth2Digest]):
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
          executionPayload, bls_to_execution_changes))

    let res = process_block(
      cfg, state.`kind Data`.data, blck.`kind Data`.asSigVerified(),
      verificationFlags, cache)
    if res.isErr:
      rollback(state)
      return err(res.error())

    # Override for MEV
    if transactions_root.isSome and execution_payload_root.isSome:
      withState(state):
        when stateFork >= BeaconStateFork.Bellatrix:
          forkyState.data.latest_execution_payload_header.transactions_root =
            transactions_root.get

          # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/specs/bellatrix/beacon-chain.md#beaconblockbody
          # Effectively hash_tree_root(ExecutionPayload) with the beacon block
          # body, with the execution payload replaced by the execution payload
          # header. htr(payload) == htr(payload header), so substitute.
          discard $capellaImplementationMissing # need different htr to match capella changes
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
             execution_payload_root.get])

    state.`kind Data`.root = hash_tree_root(state.`kind Data`.data)
    blck.`kind Data`.state_root = state.`kind Data`.root

    ok(blck)

  when T is bellatrix.ExecutionPayload:
    case state.kind
    of BeaconStateFork.Phase0:    makeBeaconBlock(phase0)
    of BeaconStateFork.Altair:    makeBeaconBlock(altair)
    of BeaconStateFork.Bellatrix: makeBeaconBlock(bellatrix)
    of BeaconStateFork.Capella, BeaconStateFork.EIP4844:
      raiseAssert "Attempt to use Bellatrix payload with post-Bellatrix state"
  elif T is capella.ExecutionPayload:
    case state.kind
    of  BeaconStateFork.Phase0, BeaconStateFork.Altair,
        BeaconStateFork.Bellatrix, BeaconStateFork.EIP4844:
      raiseAssert "Attempt to use Capella payload with non-Capella state"
    of BeaconStateFork.Capella:   makeBeaconBlock(capella)
  elif T is eip4844.ExecutionPayload:
    case state.kind
    of  BeaconStateFork.Phase0, BeaconStateFork.Altair,
        BeaconStateFork.Bellatrix, BeaconStateFork.Capella:
      raiseAssert "Attempt to use EIP4844 payload with non-EIP4844 state"
    of BeaconStateFork.EIP4844:
      debugRaiseAssert $eip4844ImplementationMissing & ": state_transition"

# workaround for https://github.com/nim-lang/Nim/issues/20900 rather than have
# these be default arguments
proc makeBeaconBlock*[T](
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState,
    proposer_index: ValidatorIndex, randao_reveal: ValidatorSig,
    eth1_data: Eth1Data, graffiti: GraffitiBytes,
    attestations: seq[Attestation], deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges, sync_aggregate: SyncAggregate,
    executionPayload: T,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackForkedHashedProc, cache: var StateCache):
    Result[ForkedBeaconBlock, cstring] =
  makeBeaconBlock(
    cfg, state, proposer_index, randao_reveal, eth1_data, graffiti,
    attestations, deposits, exits, sync_aggregate, executionPayload,
    bls_to_execution_changes, rollback, cache,
    verificationFlags = {},
    transactions_root = Opt.none Eth2Digest,
    execution_payload_root = Opt.none Eth2Digest)

proc makeBeaconBlock*[T](
    cfg: RuntimeConfig, state: var ForkedHashedBeaconState,
    proposer_index: ValidatorIndex, randao_reveal: ValidatorSig,
    eth1_data: Eth1Data, graffiti: GraffitiBytes,
    attestations: seq[Attestation], deposits: seq[Deposit],
    exits: BeaconBlockValidatorChanges, sync_aggregate: SyncAggregate,
    executionPayload: T,
    bls_to_execution_changes: SignedBLSToExecutionChangeList,
    rollback: RollbackForkedHashedProc,
    cache: var StateCache, verificationFlags: UpdateFlags):
    Result[ForkedBeaconBlock, cstring] =
  makeBeaconBlock(
    cfg, state, proposer_index, randao_reveal, eth1_data, graffiti,
    attestations, deposits, exits, sync_aggregate, executionPayload,
    bls_to_execution_changes, rollback, cache,
    verificationFlags = verificationFlags,
    transactions_root = Opt.none Eth2Digest,
    execution_payload_root = Opt.none Eth2Digest)
