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

from ../consensus_object_pools/block_pools_types import ForkChoiceBalance

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
    fcInvalidEpochRef

  Index* = int
  Delta* = int64
    ## Delta balances

  ForkChoiceError* = object
    case kind*: fcKind
    of fcFinalizedNodeUnknown,
       fcJustifiedNodeUnknown:
         blockRoot*: Eth2Digest
    of fcInconsistentTick, fcInvalidEpochRef:
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

  FcResult*[T] = Result[T, ForkChoiceError]

  ProtoNodes* = object
    buf*: seq[ProtoNode]
    offset*: int ##\
    ## Subtracted from logical index to get the physical index

  ProtoArray* = object
    currentSlot*: Slot
    confirmed*: BlockId
    checkpoints*: FinalityCheckpoints
    nodes*: ProtoNodes
    indices*: Table[Eth2Digest, Index]
    currentEpochTips*: Table[Index, FinalityCheckpoints]
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

  ValidatorInfo* = object
    balances*: seq[ForkChoiceBalance]

  BalanceCheckpoint* = object
    checkpoint*: Checkpoint
    total_active_balance*: Gwei
    validators*: ValidatorInfo

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

  ForkChoiceBackend* = object
    confirmation_byzantine_threshold*: uint64
    proto_array*: ProtoArray
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
  PayloadStatus* = uint8
 
  ForkChoiceNode* = object
    root*: Eth2Digest
    payloadStatus*: PayloadStatus

const
  # https://github.com/ethereum/consensus-specs/blob/v1.6.1/specs/gloas/fork-choice.md#constants
  PAYLOAD_TIMELY_THRESHOLD*: uint64 = PTC_SIZE div 2
  PAYLOAD_STATUS_PENDING* = PayloadStatus(0)
  PAYLOAD_STATUS_EMPTY* = PayloadStatus(1)
  PAYLOAD_STATUS_FULL* = PayloadStatus(2)

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
