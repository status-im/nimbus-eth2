# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/tables,
  ./fork_choice_types

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/fork-choice.md#new-record_payload_inclusion_list_satisfaction
func record_payload_inclusion_list_satisfaction*(
    self: var ForkChoiceBackend, root: Eth2Digest,
    is_inclusion_list_satisfied: bool) =
  ## The spec asks the execution engine inline; here the verdict arrives with
  ## payload verification, so fork choice only records it.
  self.payload_inclusion_list_satisfaction[root] = is_inclusion_list_satisfied

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-beta.0/specs/heze/fork-choice.md#new-is_payload_inclusion_list_satisfied
func is_payload_inclusion_list_satisfied*(
    self: ForkChoiceBackend, root: Eth2Digest): bool =
  ## Return whether the execution payload for the beacon block with root ``root``
  ## satisfied the inclusion list constraints, and was locally determined to be
  ## available.
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
