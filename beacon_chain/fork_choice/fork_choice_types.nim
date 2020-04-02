
# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/tables, std/options,
  # Internal
  ../spec/[datatypes, digest]

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/fork-choice.md
# This is a port of https://github.com/sigp/lighthouse/pull/804
# which is a port of "Proto-Array": https://github.com/protolambda/lmd-ghost

# ProtoArray low-level types
# ----------------------------------------------------------------------

type
  FcErrKind* = enum
    ## Fork Choice Error Kinds
    fcSuccess
    fcErrFinalizedNodeUnknown
    fcErrJustifiedNodeUnknown
    fcErrInvalidFinalizedRootCHange
    fcErrInvalidNodeIndex
    fcErrInvalidParentIndex
    fcErrInvalidBestChildIndex
    fcErrInvalidJustifiedIndex
    fcErrInvalidBestDescendant
    fcErrInvalidParentDelta
    fcErrInvalidNodeDelta
    fcErrDeltaUnderflow
    fcErrIndexUnderflow
    fcErrInvalidDeltaLen
    fcErrRevertedFinalizedEpoch
    fcErrInvalidBestNode

  FcUnderflowKind* = enum
    ## Fork Choice Overflow Kinds
     fcUnderflowIndices = "Indices Overflow"
     fcUnderflowBestChild = "Best Child Overflow"
     fcUnderflowBestDescendant = "Best Descendant Overflow"

  Index* = int
  Delta* = int
    ## Delta indices

  ForkChoiceError* = object
    case kind*: FcErrKind
    of fcSuccess:
      discard
    of fcErrFinalizedNodeUnknown,
       fcErrJustifiedNodeUnknown:
         block_root*: Eth2Digest
    of fcErrInvalidFinalizedRootChange:
      discard
    of fcErrInvalidNodeIndex,
       fcErrInvalidParentIndex,
       fcErrInvalidBestChildIndex,
       fcErrInvalidJustifiedIndex,
       fcErrInvalidBestDescendant,
       fcErrInvalidParentDelta,
       fcErrInvalidNodeDelta,
       fcErrDeltaUnderflow:
         index*: Index
    of fcErrIndexUnderflow:
      underflowKind*: FcUnderflowKind
    of fcErrInvalidDeltaLen:
      deltasLen*: int
      indicesLen*: int
    of fcErrRevertedFinalizedEpoch:
      current_finalized_epoch*: Epoch
      new_finalized_epoch*: Epoch
    of fcErrInvalidBestNode:
      start_root*: Eth2Digest
      justified_epoch*: Epoch
      finalized_epoch*: Epoch
      head_root*: Eth2Digest
      head_justified_epoch*: Epoch
      head_finalized_epoch*: Epoch

  ProtoArray* = object
    prune_threshold*: int
    justified_epoch*: Epoch
    finalized_epoch*: Epoch
    nodes*: seq[ProtoNode]
    indices*: Table[Eth2Digest, Index]

  ProtoNode* = object
    slot*: Slot
    state_root*: Eth2Digest
    root*: Eth2Digest
    parent_delta*: Option[Delta]
    justified_epoch*: Epoch
    finalized_epoch*: Epoch
    weight*: int64
    best_child*: Option[Index]
    best_descendant*: Option[Index]

const ForkChoiceSuccess* = ForkChoiceError(kind: fcSuccess)

# Fork choice high-level types
# ----------------------------------------------------------------------

type
  VoteTracker* = object
    current_root*: Eth2Digest
    next_root*: Eth2Digest
    next_epoch*: Epoch

  ForkChoice* = object
    # Note: Lighthouse is protecting all fields with Reader-Writer locks.
    #       However, given the nature of the fields, I suspect sharing those fields
    #       will lead to thread contention. For now, stay single-threaded. - Mamy
    proto_array*: ProtoArray
    votes*: seq[VoteTracker]
    balances*: seq[Gwei]
