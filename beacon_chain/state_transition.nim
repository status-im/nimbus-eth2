# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# State transition, as described in
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
#
# The purpose of this code right is primarily educational, to help piece
# together the mechanics of the beacon state and to discover potential problem
# areas. The entry point is `updateState` which is at the bottom of the file!
#
# General notes about the code (TODO):
# * It's inefficient - we quadratically copy, allocate and iterate when there
#   are faster options
# * Weird styling - the sections taken from the spec use python styling while
#   the others use NEP-1 - helps grepping identifiers in spec
# * We mix procedural and functional styles for no good reason, except that the
#   spec does so also.
# * There are likely lots of bugs.
# * For indices, we get a mix of uint64, ValidatorIndex and int - this is currently
#   swept under the rug with casts
# * The spec uses uint64 for data types, but functions in the spec often assume
#   signed bigint semantics - under- and overflows ensue
# * Sane error handling is missing in most cases (yay, we'll get the chance to
#   debate exceptions again!)
# When updating the code, add TODO sections to mark where there are clear
# improvements to be made - other than that, keep things similar to spec for
# now.

import
  algorithm, collections/sets, chronicles, math, options, sequtils, sets, tables,
  ./extras, ./ssz, ./beacon_node_types,
  ./spec/[beaconstate, bitfield, crypto, datatypes, digest, helpers, validator],
  ./spec/[state_transition_block, state_transition_epoch]

# Canonical state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
func process_slot(state: var BeaconState) =
  # Cache state root
  let previous_state_root = hash_tree_root(state)
  state.state_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    previous_state_root

  # Cache latest block header state root
  if state.latest_block_header.state_root == ZERO_HASH:
    state.latest_block_header.state_root = previous_state_root

  # Cache block root
  state.block_roots[state.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    signing_root(state.latest_block_header)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
proc process_slots*(state: var BeaconState, slot: Slot) =
  doAssert state.slot <= slot

  # Catch up to the target slot
  while state.slot < slot:
    process_slot(state)
    if (state.slot + 1) mod SLOTS_PER_EPOCH == 0:
      # Note: Genesis epoch = 0, no need to test if before Genesis
      process_epoch(state)
    state.slot += 1

# https://github.com/ethereum/eth2.0-specs/blob/v0.6.3/specs/core/0_beacon-chain.md#state-root-verification
proc verifyStateRoot(state: BeaconState, blck: BeaconBlock): bool =
  let state_root = hash_tree_root(state)
  if state_root != blck.state_root:
    notice "Block: root verification failed",
      block_state_root = blck.state_root, state_root
    false
  else:
    true

proc state_transition*(
    state: var BeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  ## Time in the beacon chain moves by slots. Every time (haha.) that happens,
  ## we will update the beacon state. Normally, the state updates will be driven
  ## by the contents of a new block, but it may happen that the block goes
  ## missing - the state updates happen regardless.
  ##
  ## Each call to this function will advance the state by one slot - new_block,
  ## must match that slot. If the update fails, the state will remain unchanged.
  ##
  ## The flags are used to specify that certain validations should be skipped
  ## for the new block. This is done during block proposal, to create a state
  ## whose hash can be included in the new block.
  #
  # TODO this function can be written with a loop inside to handle all empty
  #      slots up to the slot of the new_block - but then again, why not eagerly
  #      update the state as time passes? Something to ponder...
  #      One reason to keep it this way is that you need to look ahead if you're
  #      the block proposer, though in reality we only need a partial update for
  #      that ===> Implemented as process_slots
  # TODO There's a discussion about what this function should do, and when:
  #      https://github.com/ethereum/eth2.0-specs/issues/284

  # TODO check to which extent this copy can be avoided (considering forks etc),
  #      for now, it serves as a reminder that we need to handle invalid blocks
  #      somewhere..
  #      many functions will mutate `state` partially without rolling back
  #      the changes in case of failure (look out for `var BeaconState` and
  #      bool return values...)

  ## TODO, of cacheState/processEpoch/processSlot/processBloc, only the last
  ## might fail, so should this bother capturing here, or?
  var old_state = state

  # These should never fail.
  process_slots(state, blck.slot)

  # Block updates - these happen when there's a new block being suggested
  # by the block proposer. Every actor in the network will update its state
  # according to the contents of this block - but first they will validate
  # that the block is sane.
  # TODO what should happen if block processing fails?
  #      https://github.com/ethereum/eth2.0-specs/issues/293
  var per_epoch_cache = get_empty_per_epoch_cache()

  if processBlock(state, blck, flags, per_epoch_cache):
    # This is a bit awkward - at the end of processing we verify that the
    # state we arrive at is what the block producer thought it would be -
    # meaning that potentially, it could fail verification
    if skipValidation in flags or verifyStateRoot(state, blck):
      # State root is what it should be - we're done!
      return true

  # Block processing failed, roll back changes
  state = old_state
  false

# Hashed-state transition functions
# ---------------------------------------------------------------

# https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
func process_slot(state: var HashedBeaconState) =
  # Cache state root
  let previous_slot_state_root = state.root
  state.data.state_roots[state.data.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    previous_slot_state_root

  # Cache latest block header state root
  if state.data.latest_block_header.state_root == ZERO_HASH:
    state.data.latest_block_header.state_root = previous_slot_state_root

  # Cache block root
  state.data.block_roots[state.data.slot mod SLOTS_PER_HISTORICAL_ROOT] =
    signing_root(state.data.latest_block_header)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/core/0_beacon-chain.md#beacon-chain-state-transition-function
proc process_slots*(state: var HashedBeaconState, slot: Slot) =
  # TODO: Eth specs strongly assert that state.data.slot <= slot
  #       This prevents receiving attestation in any order
  #       (see tests/test_attestation_pool)
  #       but it maybe an artifact of the test case
  #       as this was not triggered in the testnet1
  #       after a hour
  if state.data.slot > slot:
    notice(
      "Unusual request for a slot in the past",
      current_slot = state.data.slot,
      target_slot = slot
    )

  # Catch up to the target slot
  while state.data.slot < slot:
    process_slot(state)
    if (state.data.slot + 1) mod SLOTS_PER_EPOCH == 0:
      # Note: Genesis epoch = 0, no need to test if before Genesis
      process_epoch(state.data)
    state.data.slot += 1

proc state_transition*(
    state: var HashedBeaconState, blck: BeaconBlock, flags: UpdateFlags): bool =
  # Save for rollback
  var old_state = state

  process_slots(state, blck.slot)
  var per_epoch_cache = get_empty_per_epoch_cache()

  if processBlock(state.data, blck, flags, per_epoch_cache):
    if skipValidation in flags or verifyStateRoot(state.data, blck):
      # State root is what it should be - we're done!

      # TODO when creating a new block, state_root is not yet set.. comparing
      #      with zero hash here is a bit fragile however, but this whole thing
      #      should go away with proper hash caching
      state.root =
        if blck.state_root == Eth2Digest(): hash_tree_root(state.data)
        else: blck.state_root

      return true

  # Block processing failed, roll back changes
  state = old_state
  false

# TODO document this:

# Jacek Sieka
# @arnetheduck
# Dec 21 11:32
# question about making attestations: in the attestation we carry slot and a justified_slot - just to make sure, this justified_slot is the slot that was justified when the state was at slot, not whatever the client may be seeing now? effectively, because we're attesting to MIN_ATTESTATION_INCLUSION_DELAYold states, it might be that we know about a newer justified slot, but don't include it - correct?
# Danny Ryan
# @djrtwo
# Dec 21 11:34
# You are attesting to what you see as the head of the chain at that slot
# The MIN_ATTESTATION_INCLUSION_DELAY is just how many slots must past before this message can be included on chain
# so whatever the justified_slot was inside the state that was associate with the head you are attesting to
# Jacek Sieka
# @arnetheduck
# Dec 21 11:37
# can I revise an attestation, once I get new information (about the shard or state)?
# Danny Ryan
# @djrtwo
# Dec 21 11:37
# We are attesting to the exact current state at that slot. The MIN_ATTESTATION_INCLUSION_DELAY is to attempt to reduce centralization risk in light of fast block times (ensure attestations have time to fully propagate so fair playing field on including them on chain)
# No, if you create two attestations for the same slot, you can be slashed
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#is_double_vote
# Jacek Sieka
# @arnetheduck
# Dec 21 11:39
# is there any interest for me to publish my attestation before MIN_ATTESTATION_INCLUSION_DELAY-1 time has passed?
# (apart from the risk of it not being picked up on time)
# Danny Ryan
# @djrtwo
# Dec 21 11:40

# that’s the main risk.

# Note, we’re a bit unsure about MIN_ATTESTATION_INCLUSION_DELAY because it might open up an attestors timing strategy too much. In the case where MIN_ATTESTATION_INCLUSION_DELAY is removed, we just set it to 1
# part of validator honesty assumption is to attest during your slot. That said, a rational actor might act in any number of interesting ways..
# Jacek Sieka
# @arnetheduck
# Dec 21 11:59
# I can probably google this somehow, but bls signatures, anyone knows off the top of their head if they have to be combined one by one, or can two group signatures be combined? what happens to overlap then?
# Danny Ryan
# @djrtwo
# Dec 21 12:00
# Yeah, you can do any linear combination of signatures. but you have to remember the linear combination of pubkeys that constructed
# if you have two instances of a signature from pubkey p, then you need 2*p in the group pubkey
# because the attestation bitfield is only 1 bit per pubkey right now, attestations do not support this
# it could be extended to support N overlaps up to N times per pubkey if we had N bits per validator instead of 1
# We are shying away from this for the time being. If there end up being substantial difficulties in network layer aggregation, then adding bits to aid in supporting overlaps is one potential solution
# Jacek Sieka
# @arnetheduck
# Dec 21 12:02
# ah nice, you anticipated my followup question there :) so it's not a straight-off set union operation
# Danny Ryan
# @djrtwo
# Dec 21 12:02
# depending on the particular network level troubles we run into
# right
# aggregatng sigs and pubkeys are both just ec adds https://github.com/ethereum/py-evm/blob/d82b10ae361cde6abbac62f171fcea7809c4e3cf/eth/_utils/bls.py#L191-L202
# subtractions work too (i suppose this is obvious). You can linearly combine sigs or pubs in any way
# Jacek Sieka
# @arnetheduck
# Dec 21 12:05
# hm.. well, because one thing I'm thinking of is the scenario where someone attests to some shard head and I receive that attestation.. now, let's say that's an honest attestation, but within that same slot, I have more fresh information about a shard for example.. now, I can either sign the data in the old attestation or churn out a new one, risking that neither of these get enough votes to be useful - does that sound.. accurate?
# Danny Ryan
# @djrtwo
# Dec 21 12:08

# So you won’t just be signing the head of the shard. This isn’t specified yet, but it would be targeting some recent epoch boundary to ensure higher chance of consensus.

# If your recent info is about a better fork in the shard than the one you see the other attester signed, then you are better off signing that fork because if it is winning in your few of the shard chain fork choice, then you would assume it is winning in the view of most attesters shard fork choice
# If some strange circumstance arose in which you saw a majority of attestations that signed something you think is unexpected before you signed, a rational actor might defect to this majority. An honest actor would sign what they believe to be true
# in practice, the actor would have to wait some amount of time past when they should have attested to gather this info.
# also, at the end of the day the validator has to compute the non-outsourcable proof of custody bit, so if the other validators are signing off on some shard chain fork they don’t know about, then they can’t attest to that data anyway
# (for fear of signing a bad custody bit)
# so their rational move is to just attest to the data they acutally know about and can accurately compute their proof of custody bit on
# Jacek Sieka
# @arnetheduck
# Dec 21 12:58
# what's justified_block_root doing in attestation_data? isn't that available already as get_block_root(state, attestation.data.justified_slot)?
# also, when we sign hash_tree_root(attestation.data) + bytes1(0) - what's the purpose of the 0 byte, given we have domain already?
# Danny Ryan
# @djrtwo
# Dec 21 13:03
# 0 byte is a stub for the proof of custody bit in phase 0
# If the attestation is included in a short range fork but still votes for the chain it is added to’s justified_block_root/slot, then we want to count the casper vote
# likely if I see the head of the chain as different from what ends up being the canonical chain, my view of the latest justified block might still be in accordance with the canonical chain
# if my attesation is included in a fork, the head i voted on doesn’t necessarily lead back to the justified block in the fork. Without including justified_block_root, my vote could be used in any fork for the same epoch even if the block at that justified_slot height was different
# Danny Ryan
# @djrtwo
# Dec 21 13:14
# Long story short, because attestations can be included in forks of the head they are actually attesting to, we can’t be sure of the justified_block that was being voted on by just usng the justified_slot. The security of properties of Casper FFG require that the voter makes a firm commitment to the actual source block, not just the height of the source block
# Jacek Sieka
# @arnetheduck
# Dec 21 13:23
# ok. that's quite a piece. I'm gonna have to draw some diagrams I think :)
# ah. ok. actually makes sense.. I think :)
# Jacek Sieka
# @arnetheduck
# Dec 21 13:31
# how does that interact then with the following check:

#     Verify that attestation.data.justified_block_root is equal to get_block_root_at_slot(state, attestation.data.justified_slot).

# Danny Ryan
# @djrtwo
# Dec 21 13:32
# ah, my bad above. We only include an attestation on chain if it is for the correct source
# That’s one of the bare minimum requirements to get it included on chain. Without the justified_block_root, we can’t do that check
# essentially that checks if this attestation is relevant at all to the current fork’s consensus.
# if the justified_block is wrong, then we know the target of the vote and the head of the attestation are wrong too
# sorry for the slight mix up there
# logic still holds — the justified_slot alone is not actually a firm commitment to a particular chain history. You need the associated hash
# Jacek Sieka
# @arnetheduck
# Dec 21 13:35
# can't you just follow Block.parent_root?
# well, that, and ultimately.. Block.state_root
# Danny Ryan
# @djrtwo
# Dec 21 13:37
# The block the attestation is included in might not be for the same fork the attestation was made
# we first make sure that the attestation and the block that it’s included in match at the justified_slot. if not, throw it out
# then in the incentives, we give some extra reward if the epoch_boundary_root and the chain match
# and some extra reward if the beacon_block_root match
# if all three match, then the attestation is fully agreeing with the canonical chain. +1 casper vote and strengthening the head of the fork choice
# if just justified_block_root and epoch_boundary_root match then the attestation agrees enough to successfully cast an ffg vote
# if just justified_block_root match, then at least the attestation agrees on the base of the fork choice, but this isn’t enough to cast an FFG vote
# Jacek Sieka
# @arnetheduck
# Dec 21 13:41

#     if not, throw it out

# it = block or attestation?
# Danny Ryan
# @djrtwo
# Dec 21 13:42
# well, if you are buildling the block ,you shouldn’t include it (thus throw it out of current consideration). If you are validating a block you just received and that conditon fails for an attestation, throw the block out because it included a bad attestation and is thus invalid
# The block producer knows when producing the block if they are including bad attestations or other data that will fail state transition
# and should not do that
# Jacek Sieka
# @arnetheduck
# Dec 21 13:43
# yeah, that makes sense, just checking
# ok, I think I'm gonna let that sink in a bit before asking more questions.. thanks :)
