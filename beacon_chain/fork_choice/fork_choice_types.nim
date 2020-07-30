# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[tables, options],
  # Status
  stew/results,

  chronicles,
  # Internal
  ../spec/[datatypes, digest],
  ../block_pools/block_pools_types

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/fork-choice.md
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
    fcInvalidFinalizedRootCHange
    fcInvalidNodeIndex
    fcInvalidParentIndex
    fcInvalidBestChildIndex
    fcInvalidJustifiedIndex
    fcInvalidBestDescendant
    fcInvalidParentDelta
    fcInvalidNodeDelta
    fcDeltaUnderflow
    fcIndexUnderflow
    fcInvalidDeltaLen
    fcRevertedFinalizedEpoch
    fcInvalidBestNode
    # -------------------------
    # TODO: Extra error modes beyond Proto/Lighthouse to be reviewed
    fcUnknownParent

  FcUnderflowKind* = enum
    ## Fork Choice Overflow Kinds
     fcUnderflowIndices = "Indices Overflow"
     fcUnderflowBestChild = "Best Child Overflow"
     fcUnderflowBestDescendant = "Best Descendant Overflow"

  Index* = int
  Delta* = int
    ## Delta indices

  ForkChoiceError* = object
    case kind*: fcKind
    of fcFinalizedNodeUnknown,
       fcJustifiedNodeUnknown:
         block_root*: Eth2Digest
    of fcInvalidFinalizedRootChange:
      discard
    of fcInvalidNodeIndex,
       fcInvalidParentIndex,
       fcInvalidBestChildIndex,
       fcInvalidJustifiedIndex,
       fcInvalidBestDescendant,
       fcInvalidParentDelta,
       fcInvalidNodeDelta,
       fcDeltaUnderflow:
         index*: Index
    of fcIndexUnderflow:
      underflowKind*: FcUnderflowKind
    of fcInvalidDeltaLen:
      deltasLen*: int
      indicesLen*: int
    of fcRevertedFinalizedEpoch:
      current_finalized_epoch*: Epoch
      new_finalized_epoch*: Epoch
    of fcInvalidBestNode:
      start_root*: Eth2Digest
      justified_epoch*: Epoch
      finalized_epoch*: Epoch
      head_root*: Eth2Digest
      head_justified_epoch*: Epoch
      head_finalized_epoch*: Epoch
    of fcUnknownParent:
      child_root*: Eth2Digest
      parent_root*: Eth2Digest

  FcResult*[T] = Result[T, ForkChoiceError]

  ProtoArray* = object
    prune_threshold*: int
    justified_epoch*: Epoch
    finalized_epoch*: Epoch
    nodes*: seq[ProtoNode]
    indices*: Table[Eth2Digest, Index]

  ProtoNode* = object
    root*: Eth2Digest
    parent*: Option[Index]
    justified_epoch*: Epoch
    finalized_epoch*: Epoch
    weight*: int64
    best_child*: Option[Index]
    best_descendant*: Option[Index]

  BalanceCheckpoint* = object
    blck*: BlockRef
    epoch*: Epoch
    balances*: seq[Gwei]

  FFGCheckpoints* = object
    justified*: BalanceCheckpoint
    finalized*: Checkpoint

  Checkpoints* = object
    current*: FFGCheckpoints
    best*: FFGCheckpoints
    updateAt*: Option[Epoch]

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

  ForkChoice* = object
    backend*: ForkChoiceBackend
    checkpoints*: Checkpoints
    finalizedBlock*: BlockRef ## Any finalized block used at startup

func shortlog*(vote: VoteTracker): auto =
  (
    current_root: vote.current_root,
    next_root: vote.next_root,
    next_epoch: vote.next_epoch
  )

chronicles.formatIt VoteTracker: it.shortLog
