# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  ../consensus_object_pools/[blockchain_dag, inclusion_list_pool, spec_cache],
  ../spec/inclusion_list,
  ./fork_choice_types

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.13/specs/heze/fork-choice.md#new-record_payload_inclusion_list_satisfaction
func record_payload_inclusion_list_satisfaction*(
    self: var ForkChoiceBackend, root: Eth2Digest,
    is_inclusion_list_satisfied: bool) =
  ## The spec asks the execution engine inline; here the verdict arrives with
  ## payload verification, so fork choice only records it.
  self.payload_inclusion_list_satisfaction[root] = is_inclusion_list_satisfied

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.13/specs/heze/fork-choice.md#new-is_payload_inclusion_list_satisfied
func is_payload_inclusion_list_satisfied*(
    self: ForkChoiceBackend, root: Eth2Digest): bool =
  if root notin self.proto_array.fullBlockIndices:
    return false
  # Nothing is recorded before Heze, and an optimistically imported payload is
  # recorded as satisfying, so an absent entry reads as satisfied either way.
  self.payload_inclusion_list_satisfaction.getOrDefault(root, true)

func prune_payload_inclusion_list_satisfaction*(self: var ForkChoiceBackend) =
  var staleRoots: seq[Eth2Digest]
  for root in self.payload_inclusion_list_satisfaction.keys:
    if root notin self.proto_array.indices:
      staleRoots.add root
  for root in staleRoots:
    self.payload_inclusion_list_satisfaction.del root

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.13/specs/heze/fork-choice.md#new-record_payload_inclusion_list_satisfaction
proc get_payload_inclusion_list_transactions*(
    pool: InclusionListPool, dag: ChainDAGRef, blck: BlockRef):
    Opt[seq[gloas.Transaction]] =
  ## `Opt.none` if the committee cannot be resolved, as opposed to an empty
  ## sequence, which every payload trivially satisfies.
  if blck.slot <= GENESIS_SLOT:
    return Opt.none(seq[gloas.Transaction])
  let
    slot = blck.slot - 1
    shufflingRef = dag.getShufflingRef(blck, slot.epoch, false).valueOr:
      return Opt.none(seq[gloas.Transaction])

  var committee: InclusionListCommittee
  for i, validator_index in get_inclusion_list_committee(shufflingRef, slot):
    committee[i] = validator_index

  Opt.some pool.getInclusionListTransactions(slot, committee, only_timely = true)
