# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The entry point is `state_transition` which is at the bottom of the file!
#
# General notes about the code:
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * When updating the code, add TODO sections to mark where there are clear
#   improvements to be made - other than that, keep things similar to spec unless
#   motivated by security or performance considerations

{.push raises: [Defect].}

import
  std/tables,
  chronicles,
  stew/results,
  ../extras, ../ssz/merkleization, metrics,
  ./datatypes, ./crypto, ./digest, ./helpers, ./signatures, ./validator,
  ./state_transition_block, ./state_transition_epoch,
  ../../nbench/bench_lab

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc verify_block_signature*(
    state: BeaconState, signed_block: SomeSignedBeaconBlock): bool {.nbench.} =
  let
    proposer_index = signed_block.message.proposer_index
  if proposer_index >= state.validators.lenu64:
    notice "Invalid proposer index in block",
      blck = shortLog(signed_block.message)
    return false

  if not verify_block_signature(
      state.fork, state.genesis_validators_root, signed_block.message.slot,
      signed_block.message, state.validators[proposer_index].pubkey,
      signed_block.signature):
    notice "Block: signature verification failed",
      blck = shortLog(signedBlock)
    return false

  true

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc verifyStateRoot(state: BeaconState, blck: BeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  let state_root = hash_tree_root(state)
  if state_root != blck.state_root:
    notice "Block: root verification failed",
      block_state_root = shortLog(blck.state_root), state_root = shortLog(state_root)
    false
  else:
    true

proc verifyStateRoot(state: BeaconState, blck: TrustedBeaconBlock): bool =
  # This is inlined in state_transition(...) in spec.
  true

type
  RollbackProc* = proc(v: var BeaconState) {.gcsafe, raises: [Defect].}

proc noRollback*(state: var BeaconState) =
  trace "Skipping rollback of broken state"

type
  RollbackHashedProc* = proc(state: var HashedBeaconState) {.gcsafe.}

# Hashed-state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
func process_slot*(state: var HashedBeaconState) {.nbench.} =
  # Cache state root
  let previous_slot_state_root = state.root
  state.data.state_roots[state.data.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    previous_slot_state_root

  # Cache latest block header state root
  if state.data.latest_block_header.state_root == ZERO_HASH:
    state.data.latest_block_header.state_root = previous_slot_state_root

  # Cache block root
  state.data.block_roots[state.data.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    hash_tree_root(state.data.latest_block_header)

func clear_epoch_from_cache(cache: var StateCache, epoch: Epoch) =
  cache.shuffled_active_validator_indices.del epoch
  let
    start_slot = epoch.compute_start_slot_at_epoch
    end_slot = (epoch + 1).compute_start_slot_at_epoch

  for i in start_slot ..< end_slot:
    cache.beacon_proposer_indices.del i

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc advance_slot(
    state: var HashedBeaconState, updateFlags: UpdateFlags,
    epochCache: var StateCache) {.nbench.} =
  process_slot(state)

  let is_epoch_transition = (state.data.slot + 1).isEpoch
  if is_epoch_transition:
    # Note: Genesis epoch = 0, no need to test if before Genesis
    process_epoch(state.data, updateFlags, epochCache)
    clear_epoch_from_cache(
      epochCache, (state.data.slot + 1).compute_epoch_at_slot)

  state.data.slot += 1

  # The root must be updated on every slot update, or the next `process_slot`
  # will be incorrect
  state.root = hash_tree_root(state.data)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/beacon-chain.md#beacon-chain-state-transition-function
proc process_slots*(state: var HashedBeaconState, slot: Slot,
    cache: var StateCache, updateFlags: UpdateFlags = {}): bool {.nbench.} =
  if not (state.data.slot < slot):
    if slotProcessed notin updateFlags or state.data.slot != slot:
      notice(
        "Unusual request for a slot in the past",
        state_root = shortLog(state.root),
        current_slot = state.data.slot,
        target_slot = slot
      )
      return false

  # Catch up to the target slot
  while state.data.slot < slot:
    advance_slot(state, updateFlags, cache)

  true

proc noRollback*(state: var HashedBeaconState) =
  trace "Skipping rollback of broken state"

proc state_transition*(
    preset: RuntimePreset,
    state: var HashedBeaconState, signedBlock: SomeSignedBeaconBlock,
    stateCache: var StateCache,
    flags: UpdateFlags, rollback: RollbackHashedProc): bool {.nbench.} =
  ## Time in the beacon chain moves by slots. Every time (haha.) that happens,
  ## we will update the beacon state. Normally, the state updates will be driven
  ## by the contents of a new block, but it may happen that the block goes
  ## missing - the state updates happen regardless.
  ##
  ## The flags are used to specify that certain validations should be skipped
  ## for the new block. This is done during block proposal, to create a state
  ## whose hash can be included in the new block.
  ##
  ## `rollback` is called if the transition fails and the given state has been
  ## partially changed. If a temporary state was given to `state_transition`,
  ## it is safe to use `noRollback` and leave it broken, else the state
  ## object should be rolled back to a consistent state. If the transition fails
  ## before the state has been updated, `rollback` will not be called.
  doAssert not rollback.isNil, "use noRollback if it's ok to mess up state"

  # This only fails if it hasn't changed stateCache, so it can't create a false
  # not-followed future history in stateCache.
  if not process_slots(state, signedBlock.message.slot, stateCache, flags):
    rollback(state)
    return false

  # Block updates - these happen when there's a new block being suggested
  # by the block proposer. Every actor in the network will update its state
  # according to the contents of this block - but first they will validate
  # that the block is sane.
  if skipBLSValidation in flags or
      verify_block_signature(state.data, signedBlock):

    trace "state_transition: processing block, signature passed",
      signature = shortLog(signedBlock.signature),
      blockRoot = shortLog(signedBlock.root)
    let res = process_block(preset, state.data, signedBlock.message, flags, stateCache)
    if res.isOk:
      if skipStateRootValidation in flags or verifyStateRoot(state.data, signedBlock.message):
        # State root is what it should be - we're done!

        # TODO when creating a new block, state_root is not yet set.. comparing
        #      with zero hash here is a bit fragile however, but this whole thing
        #      should go away with proper hash caching
        # TODO shouldn't ever have to recalculate; verifyStateRoot() does it
        state.root =
          if signedBlock.message.state_root == Eth2Digest(): hash_tree_root(state.data)
          else: signedBlock.message.state_root

        return true
    else:
      debug "state_transition: process_block failed",
        blck = shortLog(signedBlock.message),
        slot = state.data.slot,
        eth1_deposit_index = state.data.eth1_deposit_index,
        deposit_root = shortLog(state.data.eth1_data.deposit_root),
        error = res.error

  # Block processing failed, roll back changes
  rollback(state)

  false

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/validator.md#preparing-for-a-beaconblock
proc makeBeaconBlock*(
    preset: RuntimePreset,
    state: var HashedBeaconState,
    proposer_index: ValidatorIndex,
    parent_root: Eth2Digest,
    randao_reveal: ValidatorSig,
    eth1_data: Eth1Data,
    graffiti: GraffitiBytes,
    attestations: seq[Attestation],
    deposits: seq[Deposit],
    proposerSlashings: seq[ProposerSlashing],
    attesterSlashings: seq[AttesterSlashing],
    voluntaryExits: seq[SignedVoluntaryExit],
    rollback: RollbackHashedProc,
    cache: var StateCache): Option[BeaconBlock] =
  ## Create a block for the given state. The last block applied to it must be
  ## the one identified by parent_root and process_slots must be called up to
  ## the slot for which a block is to be created.

  # To create a block, we'll first apply a partial block to the state, skipping
  # some validations.

  var blck = BeaconBlock(
    slot: state.data.slot,
    proposer_index: proposer_index.uint64,
    parent_root: parent_root,
    body: BeaconBlockBody(
      randao_reveal: randao_reveal,
      eth1_data: eth1data,
      graffiti: graffiti,
      proposer_slashings: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS](
        proposerSlashings),
      attester_slashings: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS](
        attesterSlashings),
      attestations: List[Attestation, Limit MAX_ATTESTATIONS](attestations),
      deposits: List[Deposit, Limit MAX_DEPOSITS](deposits),
      voluntary_exits:
        List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS](voluntaryExits)))

  let res = process_block(preset, state.data, blck, {skipBlsValidation}, cache)

  if res.isErr:
    warn "Unable to apply new block to state",
      blck = shortLog(blck),
      slot = state.data.slot,
      eth1_deposit_index = state.data.eth1_deposit_index,
      deposit_root = shortLog(state.data.eth1_data.deposit_root),
      error = res.error
    rollback(state)
    return

  state.root = hash_tree_root(state.data)
  blck.state_root = state.root

  some(blck)
