# beacon_chain
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard libraries
  std/[deques, sets],
  # Internal
  ../spec/datatypes/[base, focil],
  ../spec/[helpers, state_transition_block],
  "."/[blockchain_dag]

export base, deques, blockchain_dag, focil

const
  INCLUSION_LISTS_BOUND = 1024'u64  # Reasonable bound for inclusion lists

type
  OnInclusionListCallback =
    proc(data: SignedInclusionList) {.gcsafe, raises: [].}

  InclusionListPool* = object
    ## The inclusion list pool tracks signed inclusion lists that could be
    ## added to a proposed block.

    inclusion_lists*: Deque[SignedInclusionList]  ## \
    ## Not a function of chain DAG branch; just used as a FIFO queue for blocks

    prior_seen_inclusion_list_validators: HashSet[uint64] ## \
    ## Records validator indices that have already submitted inclusion lists
    ## to prevent duplicate processing

    dag*: ChainDAGRef
    onInclusionListReceived*: OnInclusionListCallback

func init*(T: type InclusionListPool, dag: ChainDAGRef,
           onInclusionList: OnInclusionListCallback = nil): T =
  ## Initialize an InclusionListPool from the dag `headState`
  T(
    inclusion_lists:
      initDeque[SignedInclusionList](initialSize = INCLUSION_LISTS_BOUND.int),
    dag: dag,
    onInclusionListReceived: onInclusionList)

func addInclusionListMessage(
    subpool: var Deque[SignedInclusionList],
    seenpool: var HashSet[uint64],
    inclusionList: SignedInclusionList,
    bound: static[uint64]) =
  ## Add an inclusion list message to the pool, maintaining bounds
  while subpool.lenu64 >= bound:
    seenpool.excl subpool.popFirst().message.validator_index.uint64

  subpool.addLast(inclusionList)
  doAssert subpool.lenu64 <= bound

func isSeen*(pool: InclusionListPool, msg: SignedInclusionList): bool =
  ## Check if we've already seen an inclusion list from this validator
  msg.message.validator_index.uint64 in pool.prior_seen_inclusion_list_validators

proc addMessage*(pool: var InclusionListPool, msg: SignedInclusionList) =
  ## Add an inclusion list message to the pool
  pool.prior_seen_inclusion_list_validators.incl(
    msg.message.validator_index.uint64)
  
  addInclusionListMessage(
    pool.inclusion_lists, pool.prior_seen_inclusion_list_validators, msg, INCLUSION_LISTS_BOUND)

  # Send notification about new inclusion list via callback
  if not(isNil(pool.onInclusionListReceived)):
    pool.onInclusionListReceived(msg)

func getInclusionLists*(pool: InclusionListPool): seq[SignedInclusionList] =
  ## Get all inclusion lists in the pool
  result = newSeq[SignedInclusionList](pool.inclusion_lists.len)
  for i, inclusionList in pool.inclusion_lists:
    result[i] = inclusionList

func clear*(pool: var InclusionListPool) =
  ## Clear all inclusion lists from the pool
  pool.inclusion_lists.clear()
  pool.prior_seen_inclusion_list_validators.clear() 