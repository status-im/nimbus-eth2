# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[typetraits, sequtils, sets],
  stew/base10,
  chronicles, metrics,
  ./rest_utils,
  ./state_ttl_cache,
  ../beacon_node,
  ../consensus_object_pools/[blockchain_dag, spec_cache, validator_change_pool],
  ../spec/[forks, state_transition]

export rest_utils

logScope: topics = "rest_rewardsapi"

const
  GenesisBlockRewardsResponse =
    "{\"execution_optimistic\":false,\"finalized\":true,\"data\":" &
    "{\"proposer_index\":\"0\",\"total\":\"0\",\"attestations\":\"0\"," &
    "\"sync_aggregate\":\"0\",\"proposer_slashings\":\"0\"," &
    "\"attester_slashings\":\"0\"}}"

proc installRewardsApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Rewards/getBlockRewards
  router.api2(MethodGet, "/eth/v1/beacon/rewards/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      bident = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

    if (bident.kind == BlockQueryKind.Named) and
       (bident.value == BlockIdentType.Genesis):
      return RestApiResponse.response(
        GenesisBlockRewardsResponse, Http200, "application/json")

    let
      bdata = node.getForkedBlock(bident).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

      bid = BlockId(slot: bdata.slot, root: bdata.root)

      targetBlock =
        withBlck(bdata):
          let parentBid =
            node.dag.getBlockId(forkyBlck.message.parent_root).valueOr:
              return RestApiResponse.jsonError(Http404, BlockParentUnknownError)
          if parentBid.slot >= forkyBlck.message.slot:
            return RestApiResponse.jsonError(Http404, BlockOlderThanParentError)
          BlockSlotId.init(parentBid, forkyBlck.message.slot)

    var
      cache = StateCache()
      tmpState = assignClone(node.dag.headState)

    if not updateState(
      node.dag, tmpState[], targetBlock, false, cache):
        return RestApiResponse.jsonError(Http404, ParentBlockMissingStateError)

    func restore(v: var ForkedHashedBeaconState) =
      assign(node.dag.clearanceState, node.dag.headState)

    let
      rewards =
        withBlck(bdata):
          state_transition_block(
            node.dag.cfg, tmpState[], forkyBlck,
            cache, node.dag.updateFlags, restore).valueOr:
              return RestApiResponse.jsonError(Http400, BlockInvalidError)
      total = rewards.attestations + rewards.sync_aggregate +
              rewards.proposer_slashings + rewards.attester_slashings
      proposerIndex =
        withBlck(bdata):
          forkyBlck.message.proposer_index

    RestApiResponse.jsonResponseFinalized(
      (
        proposer_index: Base10.toString(uint64(proposerIndex)),
        total: Base10.toString(uint64(total)),
        attestations: Base10.toString(uint64(rewards.attestations)),
        sync_aggregate: Base10.toString(uint64(rewards.sync_aggregate)),
        proposer_slashings: Base10.toString(uint64(rewards.proposer_slashings)),
        attester_slashings: Base10.toString(uint64(rewards.attester_slashings))
      ),
      node.getBlockOptimistic(bdata),
      node.dag.isFinalized(bid)
    )
