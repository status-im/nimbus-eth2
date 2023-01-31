# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard library
  std/tables,
  # Status
  stew/results,
  chronicles,
  # Internal
  ../spec/datatypes/base,
  ../spec/helpers

# https://github.com/ethereum/consensus-specs/blob/v0.11.1/specs/phase0/fork-choice.md
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
    experimental*: bool
    hasLowParticipation*: bool
    currentEpoch*: Epoch
    checkpoints*: FinalityCheckpoints
    nodes*: ProtoNodes
    indices*: Table[Eth2Digest, Index]
    currentEpochTips*: Table[Index, FinalityCheckpoints]
    previousProposerBoostRoot*: Eth2Digest
    previousProposerBoostScore*: uint64

  ProtoNode* = object
    bid*: BlockId
    parent*: Option[Index]
    checkpoints*: FinalityCheckpoints
    weight*: int64
    invalid*: bool
    bestChild*: Option[Index]
    bestDescendant*: Option[Index]

  BalanceCheckpoint* = object
    checkpoint*: Checkpoint
    balances*: seq[Gwei]

  Checkpoints* = object
    experimental*: bool
    time*: BeaconTime
    justified*: BalanceCheckpoint
    finalized*: Checkpoint
    best_justified*: Checkpoint
    proposer_boost_root*: Eth2Digest

# Fork choice high-level types
# ----------------------------------------------------------------------

type
  VoteTracker* = object
    current_root*: Eth2Digest
    next_root*: Eth2Digest
    next_epoch*: Epoch

  ForkChoiceBackend* = object
    proto_array*: ProtoArray
    votes*: seq[VoteTracker]
    balances*: seq[Gwei]

  QueuedAttestation* = object
    slot*: Slot
    attesting_indices*: seq[ValidatorIndex]
    block_root*: Eth2Digest
    target_epoch*: Epoch

  ForkChoice* = object
    backend*: ForkChoiceBackend
    checkpoints*: Checkpoints
    queuedAttestations*: seq[QueuedAttestation]

func shortLog*(vote: VoteTracker): auto =
  (
    current_root: shortLog(vote.current_root),
    next_root: shortLog(vote.next_root),
    next_epoch: vote.next_epoch
  )

chronicles.formatIt VoteTracker: it.shortLog
chronicles.formatIt ForkChoiceError: $it
