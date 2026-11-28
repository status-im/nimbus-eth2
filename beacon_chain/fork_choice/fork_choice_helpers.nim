# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  ../consensus_object_pools/blockchain_dag,
  ./[fork_choice_types, proto_array]

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.5/specs/phase0/fork-choice.md#is_proposer_equivocation
proc is_proposer_equivocation*(
    self: ForkChoice, dag: ChainDAGRef, root: Eth2Digest): bool =
  let
    blck = dag.getBlockRef(root).valueOr: return false
    proposer = dag.getProposer(blck, blck.slot).valueOr: return false
  var count = 0
  template nodes(): auto = self.backend.proto_array.nodes.buf
  for i in 0 ..< nodes.len():
    if nodes[i].bid.slot != blck.slot: continue

    let other = dag.getBlockRef(nodes[i].bid.root).valueOr: continue
    if dag.getProposer(other, other.slot) == Opt.some(proposer):
      inc count
  count > 1
