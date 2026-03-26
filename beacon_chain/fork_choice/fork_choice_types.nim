# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard library
  std/tables,
  # Status
  results,
  chronicles,
  # Internal
  ../spec/datatypes/base,
  ../spec/helpers

from ../consensus_object_pools/block_pools_types import
  BlockRef, EpochRef, ForkChoiceBalance

export results, base

# https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/fork-choice.md
# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost
# See also:
# - Protolambda port of Lighthouse: https://github.com/protolambda/eth2-py-hacks/blob/ae286567/proto_array.py
# - Prysmatic writeup: https://hackmd.io/bABJiht3Q9SyV3Ga4FT9lQ#High-level-concept
# - Gasper Whitepaper: https://arxiv.org/abs/2003.03052

# ProtoArray low-level types
# ----------------------------------------------------------------------

type
  fcKind* = enum
    ## Fork Choice Error Kinds
    fcFinalizedNodeUnknown
    fcJustifiedNodeUnknown
    fcConfirmedNodeUnknown
    fcPreviousHeadUnknown
    fcCurrentHeadUnknown
    fcInvalidNodeIndex
    fcInvalidJustifiedIndex
    fcInvalidBestDescendant
    fcInvalidParentDelta
    fcInvalidNodeDelta
    fcDeltaUnderflow
    fcDeltaOverflow
    fcInvalidDeltaLen
    fcInvalidBestNode
    fcInconsistentTick
    fcUnknownParent
    fcPruningFromOutdatedFinalizedRoot
    fcUnknownBlockIdAtSlot
    fcUnknownShufflingRef

  Index* = int
  Delta* = int64
    ## Delta balances
  
  # https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#custom-types
  PayloadStatus* = uint8

  ForkChoiceError* = object
    case kind*: fcKind
    of fcFinalizedNodeUnknown,
       fcJustifiedNodeUnknown,
       fcConfirmedNodeUnknown,
       fcPreviousHeadUnknown,
       fcCurrentHeadUnknown:
         blockRoot*: Eth2Digest
    of fcInconsistentTick:
      discard
    of fcInvalidNodeIndex,
       fcInvalidJustifiedIndex,
       fcInvalidBestDescendant,
       fcInvalidParentDelta,
       fcInvalidNodeDelta,
       fcDeltaUnderflow,
       fcDeltaOverflow:
         index*: Index
    of fcInvalidDeltaLen:
      deltasLen*: int
      indicesLen*: int
    of fcInvalidBestNode:
      startRoot*: Eth2Digest
      fkChoiceCheckpoints*: FinalityCheckpoints
      headRoot*: Eth2Digest
      headCheckpoints*: FinalityCheckpoints
    of fcUnknownParent:
      childRoot*: Eth2Digest
      parentRoot*: Eth2Digest
    of fcPruningFromOutdatedFinalizedRoot:
      finalizedRoot*: Eth2Digest
    of fcUnknownBlockIdAtSlot,
       fcUnknownShufflingRef:
         shufflingRoot*: Eth2Digest
         shufflingEpoch*: Epoch

  FcResult*[T] = Result[T, ForkChoiceError]

  ProtoNodes* = object
    buf*: seq[ProtoNode]
    offset*: int ##\
    ## Subtracted from logical index to get the physical index

  ProtoArray* = object
    currentSlot*: Slot
    checkpoints*: FinalityCheckpoints
    nodes*: ProtoNodes
    indices*: Table[Eth2Digest, Index]
    unrealized*: Table[Index, FinalityCheckpoints]
    previousProposerBoostRoot*: Eth2Digest
    previousProposerBoostScore*: Gwei

  ProtoNode* = object
    bid*: BlockId
    parent*: Opt[Index]
    checkpoints*: FinalityCheckpoints
    sharedFinalizedEpoch*: Epoch
    weight*: int64
    invalid*: bool
    bestChild*: Opt[Index]
    bestDescendant*: Opt[Index]
    parentPayloadStatus*: PayloadStatus

  BalanceCheckpoint* = object
    checkpoint*: Checkpoint
    total_active_balance*: Gwei
    balances*: seq[ForkChoiceBalance]

  Checkpoints* = object
    time*: BeaconTime
    justified*: BalanceCheckpoint
    finalized*: Checkpoint
    proposer_boost_root*: Eth2Digest

# Fork choice high-level types
# ----------------------------------------------------------------------

type
  VoteTracker* = object
    current_root*: Eth2Digest
    next_root*: Eth2Digest
    slot*: Slot
    next_epoch*: Epoch
    next_slot*: Slot
    payload_present*: bool
  
  PtcVotes* = BitArray[int(PTC_SIZE)]

  BalanceSource* = object
    # Effective balances / slashings in `info` based on historical checkpoint.
    # The `assigned_slots` (`fast_confirmation.nim`) are based on `dag.head`
    # and overlap the top bits of `info.balances`. `fork_choice.nim` transfers
    # them from the old to the new `BalanceSource` when it changes.
    info*: BalanceCheckpoint
    shuffling_epochs*: array[3, Epoch]
    shuffling_roots*: array[3, Eth2Digest]

  ForkChoiceBackend* = object
    confirmation_byzantine_threshold*: uint64
    proto_array*: ProtoArray
    confirmed*: BlockId
    current_epoch_observed_justified*: BalanceSource
    previous_epoch_greatest_unrealized_checkpoint*: Checkpoint
    previous_slot_head*, current_slot_head*: Eth2Digest
    votes*: seq[VoteTracker]
    balances*: seq[ForkChoiceBalance]
    # Additional state tracking for Gloas
    execution_payload_states*: Table[Eth2Digest, Eth2Digest] # root -> state_root
    ptc_vote*: Table[Eth2Digest, PtcVotes]

  QueuedAttestation* = object
    attesting_indices*: seq[ValidatorIndex]
    block_root*: Eth2Digest
    target_epoch*: Epoch
    # Gloas - track committee index for payload preference
    committee_index*: CommitteeIndex
    slot*: Slot

  ForkChoice* = object
    backend*: ForkChoiceBackend
    checkpoints*: Checkpoints
    queuedAttestations*: seq[QueuedAttestation]

# New Fork choice types for Gloas
# ----------------------------------------------------------------------

type
  # https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#custom-types
  ForkChoiceNode* = object
    root*: Eth2Digest
    payloadStatus*: PayloadStatus

const
  # https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.2/specs/gloas/fork-choice.md#constants
  PAYLOAD_TIMELY_THRESHOLD*: uint64 = PTC_SIZE div 2
  PAYLOAD_STATUS_PENDING* = PayloadStatus(0)
  PAYLOAD_STATUS_EMPTY* = PayloadStatus(1)
  PAYLOAD_STATUS_FULL* = PayloadStatus(2)
  ATTESTATION_TIMELINESS_INDEX*: uint8 = 0
  PTC_TIMELINESS_INDEX*: uint8 = 1
  NUM_BLOCK_TIMELINESS_DEADLINES*: uint8 = 2

func shortLog*(vote: VoteTracker): auto =
  (
    slot: vote.slot,
    current_root: shortLog(vote.current_root),
    next_root: shortLog(vote.next_root),
    next_epoch: vote.next_epoch,
    next_slot: vote.next_slot,
    payload_present: vote.payload_present
  )

chronicles.formatIt VoteTracker: it.shortLog
chronicles.formatIt ForkChoiceError: $it

func extend*[T](s: var seq[T], minLen: int) =
  ## Extend a sequence so that it can contains at least `minLen` elements.
  ## If it's already bigger, the sequence is unmodified.
  ## The extension is zero-initialized
  if s.len < minLen:
    s.setLen(minLen)

template to_balance_checkpoint*(
    epochRef: EpochRef, blck: BlockRef): BalanceCheckpoint =
  BalanceCheckpoint(
    checkpoint: Checkpoint(root: blck.root, epoch: epochRef.epoch),
    total_active_balance: epochRef.total_active_balance,
    balances: epochRef.fork_choice_balances)

template checkpoint*(balance_source: BalanceSource): Checkpoint =
  balance_source.info.checkpoint

template total_active_balance*(balance_source: BalanceSource): Gwei =
  balance_source.info.total_active_balance

template balances*(balance_source: BalanceSource): seq[ForkChoiceBalance] =
  balance_source.info.balances
