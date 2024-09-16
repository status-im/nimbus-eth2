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

proc installRewardsApiHandlers*(router: var RestRouter, node: BeaconNode) =
  let
    genesisBlockRewardsResponse =
      RestApiResponse.prepareJsonResponseFinalized(
        (
          proposer_index: "0", total: "0", attestations: "0",
          sync_aggregate: "0", proposer_slashings: "0", attester_slashings: "0"
        ),
        Opt.some(false),
        true,
      )

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
        genesisBlockRewardsResponse, Http200, "application/json")

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

  # https://ethereum.github.io/beacon-APIs/#/Rewards/getSyncCommitteeRewards
  router.api2(
    MethodPost, "/eth/v1/beacon/rewards/sync_committee/{block_id}") do (
      block_id: BlockIdent,
      contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      idents =
        block:
          if contentBody.isNone():
            return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
          let res = decodeBody(seq[ValidatorIdent], contentBody.get()).valueOr:
            return RestApiResponse.jsonError(
              Http400, InvalidRequestBodyError, $error)
          res

      bident = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)
      bdata = node.getForkedBlock(bident).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)

      bid = BlockId(slot: bdata.slot, root: bdata.root)

      sync_aggregate =
        withBlck(bdata):
          when consensusFork > ConsensusFork.Phase0:
            forkyBlck.message.body.sync_aggregate
          else:
            default(TrustedSyncAggregate)

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

    let response =
      withState(tmpState[]):
        var resp: seq[RestSyncCommitteeReward]
        when consensusFork > ConsensusFork.Phase0:
          let
            keys =
              block:
                var res: seq[ValidatorPubKey]
                for item in idents:
                  case item.kind
                  of ValidatorQueryKind.Index:
                    let vindex = item.index.toValidatorIndex().valueOr:
                      case error
                      of ValidatorIndexError.TooHighValue:
                        return RestApiResponse.jsonError(
                          Http400, TooHighValidatorIndexValueError)
                      of ValidatorIndexError.UnsupportedValue:
                        return RestApiResponse.jsonError(
                          Http500, UnsupportedValidatorIndexValueError)
                    if uint64(vindex) >= lenu64(forkyState.data.validators):
                      return RestApiResponse.jsonError(
                        Http400, ValidatorNotFoundError)
                    res.add(forkyState.data.validators.item(vindex).pubkey)
                  of ValidatorQueryKind.Key:
                    res.add(item.key)
                toHashSet(res)

            committeeKeys =
              toHashSet(forkyState.data.current_sync_committee.pubkeys.data)

            pubkeyIndices =
              block:
                var res: Table[ValidatorPubKey, ValidatorIndex]
                for vindex in forkyState.data.validators.vindices:
                  let pubkey = forkyState.data.validators.item(vindex).pubkey
                  if pubkey in committeeKeys:
                    res[pubkey] = vindex
                res

          for i in 0 ..< min(len(forkyState.data.current_sync_committee.pubkeys),
                             len(sync_aggregate.sync_committee_bits)):
            let
              pubkey = forkyState.data.current_sync_committee.pubkeys.data[i]
              vindex = pubkeyIndices.getOrDefault(pubkey)

            if (len(idents) == 0) or (pubkey in keys):
              resp.add(RestSyncCommitteeReward(
                validator_index: RestValidatorIndex(vindex),
                reward: uint64(get_participant_reward(
                  forkyState.data.balances.item(vindex)))
              ))
        resp


    RestApiResponse.jsonResponseFinalized(
      response,
      node.getBlockOptimistic(bdata),
      node.dag.isFinalized(bid)
    )
