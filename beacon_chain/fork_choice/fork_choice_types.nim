# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/[options, tables],
  # Status
  stew/results,

  chronicles,
  # Internal
  ../beacon_clock,
  ../spec/datatypes/base,
  ../consensus_object_pools/block_pools_types

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
    fcInvalidDeltaLen
    fcInvalidBestNode
    fcInconsistentTick
    fcUnknownParent
    fcPruningFromOutdatedFinalizedRoot

  Index* = int
  Delta* = int64
    ## Delta balances

  ForkChoiceError* = object
    case kind*: fcKind
    of fcFinalizedNodeUnknown,
       fcJustifiedNodeUnknown:
         blockRoot*: Eth2Digest
    of fcInconsistentTick:
      discard
    of fcInvalidNodeIndex,
       fcInvalidJustifiedIndex,
       fcInvalidBestDescendant,
       fcInvalidParentDelta,
       fcInvalidNodeDelta,
       fcDeltaUnderflow:
         index*: Index
    of fcInvalidDeltaLen:
      deltasLen*: int
      indicesLen*: int
    of fcInvalidBestNode:
      startRoot*: Eth2Digest
      fkChoiceJustifiedCheckpoint*: Checkpoint
      fkChoiceFinalizedCheckpoint*: Checkpoint
      headRoot*: Eth2Digest
      headJustifiedCheckpoint*: Checkpoint
      headFinalizedCheckpoint*: Checkpoint
    of fcUnknownParent:
      childRoot*: Eth2Digest
      parentRoot*: Eth2Digest
    of fcPruningFromOutdatedFinalizedRoot:
      finalizedRoot*: Eth2Digest

  FcResult*[T] = Result[T, ForkChoiceError]

  ProtoNodes* = object
    buf*: seq[ProtoNode]
    offset*: int ##\
    ## Substracted from logical Index
    ## to get the physical index

  ProtoArray* = object
    justifiedCheckpoint*: Checkpoint
    finalizedCheckpoint*: Checkpoint
    nodes*: ProtoNodes
    indices*: Table[Eth2Digest, Index]

  ProtoNode* = object
    root*: Eth2Digest
    parent*: Option[Index]
    justifiedCheckpoint*: Checkpoint
    finalizedCheckpoint*: Checkpoint
    weight*: int64
    bestChild*: Option[Index]
    bestDescendant*: Option[Index]

  BalanceCheckpoint* = object
    checkpoint*: Checkpoint
    balances*: seq[Gwei]

  Checkpoints* = object
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

func shortlog*(vote: VoteTracker): auto =
  (
    current_root: vote.current_root,
    next_root: vote.next_root,
    next_epoch: vote.next_epoch
  )

chronicles.formatIt VoteTracker: it.shortLog
chronicles.formatIt ForkChoiceError: $it
