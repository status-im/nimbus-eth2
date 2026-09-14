# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[typetraits, sets],
  stew/base10,
  chronicles, metrics,
  ./rest_utils,
  ../beacon_node,
  ../consensus_object_pools/[blockchain_dag, spec_cache, validator_change_pool],
  ../spec/[beaconstate, forks, state_transition, state_transition_epoch]

export rest_utils

logScope: topics = "rest_rewardsapi"

func isGenesis(node: BeaconNode,
               blockId: BlockIdent,
               genesisBsid: BlockSlotId): bool =
  case blockId.kind
  of BlockQueryKind.Named:
    case blockId.value
    of BlockIdentType.Genesis:
      true
    of BlockIdentType.Head:
      node.dag.head.bid.slot == GENESIS_SLOT
    of BlockIdentType.Finalized:
      node.dag.finalizedHead.slot == GENESIS_SLOT
  of BlockQueryKind.Slot:
    blockId.slot == GENESIS_SLOT
  of BlockQueryKind.Root:
    blockId.root == genesisBsid.bid.root

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
    genesisBsid = node.dag.getBlockIdAtSlot(GENESIS_SLOT).get()

  # https://ethereum.github.io/beacon-APIs/#/Rewards/getBlockRewards
  router.api2(MethodGet, "/eth/v1/beacon/rewards/blocks/{block_id}") do (
    block_id: BlockIdent) -> RestApiResponse:
    let
      bident = block_id.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidBlockIdValueError,
                                         $error)

    if node.isGenesis(bident, genesisBsid):
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
      node.dag, tmpState[], targetBlock, false, cache, node.dag.updateFlags):
        return RestApiResponse.jsonError(Http404, ParentBlockMissingStateError)

    func rollbackProc(state: var ForkedHashedBeaconState) {.
         gcsafe, noSideEffect, raises: [].} =
      discard

    let
      rewards =
        withBlck(bdata):
          state_transition_block(
            node.dag.cfg, tmpState[], forkyBlck,
            cache, node.dag.updateFlags, rollbackProc).valueOr:
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
      contentBody: Opt[ContentBody]) -> RestApiResponse:
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
          if node.isGenesis(bident, genesisBsid):
            genesisBsid
          else:
            let parentBid =
              node.dag.getBlockId(forkyBlck.message.parent_root).valueOr:
                return RestApiResponse.jsonError(
                  Http404, BlockParentUnknownError)
            if parentBid.slot >= forkyBlck.message.slot:
              return RestApiResponse.jsonError(
                Http404, BlockOlderThanParentError)
            BlockSlotId.init(parentBid, forkyBlck.message.slot)

    var
      cache = StateCache()
      tmpState = assignClone(node.dag.headState)

    if not updateState(
      node.dag, tmpState[], targetBlock, false, cache, node.dag.updateFlags):
        return RestApiResponse.jsonError(Http404, ParentBlockMissingStateError)

    let response =
      withState(tmpState[]):
        var resp: seq[RestSyncCommitteeReward]
        when consensusFork > ConsensusFork.Phase0:
          let
            total_active_balance =
              get_total_active_balance(forkyState.data, cache)
            keys =
              block:
                var res: HashSet[ValidatorPubKey]
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
                    res.incl(forkyState.data.validators.item(vindex).pubkey)
                  of ValidatorQueryKind.Key:
                    res.incl(item.key)
                res

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
            reward =
              block:
                let res = uint64(get_participant_reward(total_active_balance))
                if res > uint64(high(int64)):
                  return RestApiResponse.jsonError(
                    Http500, RewardOverflowError)
                res

          for i in 0 ..< min(
            len(forkyState.data.current_sync_committee.pubkeys),
            len(sync_aggregate.sync_committee_bits)):
            let
              pubkey = forkyState.data.current_sync_committee.pubkeys.data[i]
              vindex =
                try:
                  pubkeyIndices[pubkey]
                except KeyError:
                  raiseAssert "Unknown sync committee pubkey encountered!"
              vreward =
                if sync_aggregate.sync_committee_bits[i]:
                  cast[int64](reward)
                else:
                  -cast[int64](reward)

            if (len(idents) == 0) or (pubkey in keys):
              resp.add(RestSyncCommitteeReward(
                validator_index: RestValidatorIndex(vindex),
                reward: RestReward(vreward)))

        resp

    RestApiResponse.jsonResponseFinalized(
      response,
      node.getBlockOptimistic(bdata),
      node.dag.isFinalized(bid)
    )

  # https://ethereum.github.io/beacon-APIs/#/Rewards/getAttestationsRewards
  router.api2(
    MethodPost, "/eth/v1/beacon/rewards/attestations/{epoch}") do (
      epoch: Epoch, contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      qepoch = epoch.valueOr:
        return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                         $error)

      idents =
        if contentBody.isSome():
          decodeBody(seq[ValidatorIdent], contentBody.get()).valueOr:
            return RestApiResponse.jsonError(
              Http400, InvalidRequestBodyError, $error)
        else:
          default(seq[ValidatorIdent])

    # `qepoch + 2` must not overflow when computing the state slot below
    if qepoch >= MaxEpoch - 2:
      return RestApiResponse.jsonError(Http400, EpochOverflowValueError)

    # Attestation rewards for `epoch` are applied during the transition at the
    # end of `epoch + 1`, so the pre-transition state at its last slot is needed.
    let stateSlot = (qepoch + 2).start_slot() - 1
    if stateSlot > node.dag.head.slot:
      return RestApiResponse.jsonError(
        Http404, StateNotFoundError,
        "Requested epoch rewards are not available yet")

    let bsi = node.dag.getBlockIdAtSlot(stateSlot).valueOr:
      return RestApiResponse.jsonError(Http404, StateNotFoundError)

    var
      cache = StateCache()
      tmpState = assignClone(node.dag.headState)

    if not updateState(
      node.dag, tmpState[], bsi, false, cache, node.dag.updateFlags):
        return RestApiResponse.jsonError(Http404, StateNotFoundError)

    # An empty `selected` reports every eligible validator
    var
      selected: HashSet[ValidatorIndex]
      keys: seq[ValidatorPubKey]
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
              Http400, UnsupportedValidatorIndexValueError)
        if uint64(vindex) >= lenu64(tmpState[].validators):
          return RestApiResponse.jsonError(Http400, ValidatorNotFoundError)
        selected.incl(vindex)
      of ValidatorQueryKind.Key:
        keys.add(item.key)

    for optIndex in keysToIndices(node.restKeysCache, tmpState[], keys):
      let vindex = optIndex.valueOr:
        return RestApiResponse.jsonError(Http400, ValidatorNotFoundError)
      selected.incl(vindex)

    let response =
      withState(tmpState[]):
        when consensusFork >= ConsensusFork.Altair:
          let rewards = get_attestation_rewards(
            node.dag.cfg, forkyState.data, cache, node.dag.updateFlags,
            selected)

          var res: RestAttestationsRewards
          for reward in rewards.ideal_rewards:
            res.ideal_rewards.add RestIdealAttestationReward(
              effective_balance: uint64(reward.effective_balance),
              head: RestReward(reward.head),
              target: RestReward(reward.target),
              source: RestReward(reward.source),
              # Ideal participation is never penalized for inactivity
              inactivity: RestReward(0))
          for reward in rewards.total_rewards:
            res.total_rewards.add RestTotalAttestationReward(
              validator_index: RestValidatorIndex(reward.validator_index),
              head: RestReward(reward.head),
              target: RestReward(reward.target),
              source: RestReward(reward.source),
              inactivity: RestReward(reward.inactivity))
          res
        else:
          return RestApiResponse.jsonError(
            Http400, UnsupportedForkError,
            "Attestation rewards are not available before the Altair fork")

    RestApiResponse.jsonResponseFinalized(
      response,
      node.getStateOptimistic(tmpState[]),
      node.dag.isFinalized(bsi.bid)
    )
