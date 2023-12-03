# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[typetraits, sets, sequtils]
import stew/[results, base10], chronicles
import ".."/[beacon_chain_db, beacon_node],
       ".."/networking/eth2_network,
       ".."/consensus_object_pools/[blockchain_dag, spec_cache,
                                    attestation_pool, sync_committee_msg_pool],
       ".."/validators/beacon_validators,
       ".."/spec/[beaconstate, forks, network],
       ".."/spec/datatypes/[phase0, altair],
       "."/[rest_utils, state_ttl_cache]

from ".."/spec/datatypes/bellatrix import ExecutionPayload
from ".."/spec/datatypes/capella import ExecutionPayload

export rest_utils

logScope: topics = "rest_validatorapi"

proc installValidatorApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties
  router.api(MethodPost, "/eth/v1/validator/duties/attester/{epoch}") do (
    epoch: Epoch, contentBody: Option[ContentBody]) -> RestApiResponse:
    let indexList =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[RestValidatorIndex], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidValidatorIndexValueError,
                                           $dres.error())
        var res: HashSet[ValidatorIndex]
        let items = dres.get()
        for item in items:
          let vres = item.toValidatorIndex()
          if vres.isErr():
            case vres.error()
            of ValidatorIndexError.TooHighValue:
              return RestApiResponse.jsonError(Http400,
                                               TooHighValidatorIndexValueError)
            of ValidatorIndexError.UnsupportedValue:
              return RestApiResponse.jsonError(Http500,
                                            UnsupportedValidatorIndexValueError)
          res.incl(vres.get())
        if len(res) == 0:
          return RestApiResponse.jsonError(Http400,
                                           EmptyValidatorIndexArrayError)
        res
    let qepoch =
      block:
        if epoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $epoch.error())
        let
          res = epoch.get()
          wallTime = node.beaconClock.now() + MAXIMUM_GOSSIP_CLOCK_DISPARITY
          wallEpoch = wallTime.slotOrZero().epoch
        if res > wallEpoch + 1:
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                        "Cannot request duties past next epoch")
        res
    let qhead =
      block:
        let res = node.getSyncedHead(qepoch)
        if res.isErr():
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                           $res.error())
        res.get()
    let shufflingRef = node.dag.getShufflingRef(qhead, qepoch, true).valueOr:
      return RestApiResponse.jsonError(Http400, PrunedStateError)

    let duties =
      block:
        var res: seq[RestAttesterDuty]

        let
          committees_per_slot = get_committee_count_per_slot(shufflingRef)
        for committee_index in get_committee_indices(committees_per_slot):
          for slot in qepoch.slots():
            let
              committee =
                get_beacon_committee(shufflingRef, slot, committee_index)
            for index_in_committee, validator_index in committee:
              if validator_index in indexList:
                let validator_key = node.dag.validatorKey(validator_index)
                if validator_key.isSome():
                  res.add(
                    RestAttesterDuty(
                      pubkey: validator_key.get().toPubKey(),
                      validator_index: validator_index,
                      committee_index: committee_index,
                      committee_length: lenu64(committee),
                      committees_at_slot: committees_per_slot,
                      validator_committee_index: uint64(index_in_committee),
                      slot: slot
                    )
                  )
        res

    let optimistic = node.getShufflingOptimistic(
      shufflingRef.attester_dependent_slot,
      shufflingRef.attester_dependent_root)

    return RestApiResponse.jsonResponseWRoot(
      duties, shufflingRef.attester_dependent_root, optimistic)

  # https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties
  router.api(MethodGet, "/eth/v1/validator/duties/proposer/{epoch}") do (
    epoch: Epoch) -> RestApiResponse:
    let qepoch =
      block:
        if epoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $epoch.error())
        let
          res = epoch.get()
          wallTime = node.beaconClock.now() + MAXIMUM_GOSSIP_CLOCK_DISPARITY
          wallEpoch = wallTime.slotOrZero().epoch
        if res > wallEpoch + 1:
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                        "Cannot request duties past next epoch")
        res
    let qhead =
      block:
        let res = node.getSyncedHead(qepoch)
        if res.isErr():
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                           $res.error())
        res.get()
    let epochRef = node.dag.getEpochRef(qhead, qepoch, true).valueOr:
      return RestApiResponse.jsonError(Http400, PrunedStateError, $error)

    let duties =
      block:
        var res: seq[RestProposerDuty]
        for i, bp in epochRef.beacon_proposers:
          if i == 0 and qepoch == 0:
            # Fix for https://github.com/status-im/nimbus-eth2/issues/2488
            # Slot(0) at Epoch(0) do not have a proposer.
            continue

          if bp.isSome():
            res.add(
              RestProposerDuty(
                pubkey: node.dag.validatorKey(bp.get()).get().toPubKey(),
                validator_index: bp.get(),
                slot: qepoch.start_slot() + i
              )
            )
        res

    let optimistic = node.getShufflingOptimistic(
      epochRef.proposer_dependent_slot,
      epochRef.proposer_dependent_root)

    return RestApiResponse.jsonResponseWRoot(
      duties, epochRef.proposer_dependent_root, optimistic)

  # https://ethereum.github.io/beacon-APIs/#/Validator/getSyncCommitteeDuties
  router.api(MethodPost, "/eth/v1/validator/duties/sync/{epoch}") do (
    epoch: Epoch, contentBody: Option[ContentBody]) -> RestApiResponse:
    let indexList =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[RestValidatorIndex], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidValidatorIndexValueError,
                                           $dres.error())
        var res: seq[ValidatorIndex]
        let items = dres.get()
        for item in items:
          let vres = item.toValidatorIndex()
          if vres.isErr():
            case vres.error()
            of ValidatorIndexError.TooHighValue:
              return RestApiResponse.jsonError(Http400,
                                               TooHighValidatorIndexValueError)
            of ValidatorIndexError.UnsupportedValue:
              return RestApiResponse.jsonError(Http500,
                                            UnsupportedValidatorIndexValueError)
          res.add(vres.get())
        if len(res) == 0:
          return RestApiResponse.jsonError(Http400,
                                           EmptyValidatorIndexArrayError)
        res
    let qepoch =
      block:
        if epoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $epoch.error())
        let res = epoch.get()
        if res > MaxEpoch:
          return RestApiResponse.jsonError(Http400, EpochOverflowValueError)

        res

    # We use a local proc in order to:
    # * avoid code duplication
    # * reduce code bloat from `withState`
    proc produceResponse(requestedValidatorIndices: openArray[ValidatorIndex],
                         syncCommittee: openArray[ValidatorPubKey],
                         stateValidators: seq[Validator]
                        ): seq[RestSyncCommitteeDuty] {.nimcall.} =
      result = newSeqOfCap[RestSyncCommitteeDuty](len(requestedValidatorIndices))
      for requestedValidatorIdx in requestedValidatorIndices:
        if requestedValidatorIdx.uint64 >= stateValidators.lenu64:
          # If the requested validator index was not valid within this old
          # state, it's not possible that it will sit on the sync committee.
          # Since this API must omit results for validators that don't have
          # duties, we can simply ingnore this requested index.
          # (we won't bother to validate it against a more recent state).
          continue

        let requestedValidatorPubkey =
          stateValidators[requestedValidatorIdx].pubkey

        var indicesInSyncCommittee = newSeq[IndexInSyncCommittee]()
        for idx, syncCommitteeMemberPubkey in syncCommittee:
          if syncCommitteeMemberPubkey == requestedValidatorPubkey:
            indicesInSyncCommittee.add(IndexInSyncCommittee idx)

        if indicesInSyncCommittee.len > 0:
          result.add RestSyncCommitteeDuty(
            pubkey: requestedValidatorPubkey,
            validator_index: requestedValidatorIdx,
            validator_sync_committee_indices: indicesInSyncCommittee)

    template emptyResponse: auto =
      newSeq[RestSyncCommitteeDuty]()

    # We check the head state first in order to avoid costly replays
    # if possible:
    let
      qSyncPeriod = sync_committee_period(qepoch)
      headEpoch = node.dag.head.slot.epoch
      headSyncPeriod = sync_committee_period(headEpoch)

      dependentSlot = max(
        node.dag.cfg.ALTAIR_FORK_EPOCH.start_slot,
        if qSyncPeriod >= 2.SyncCommitteePeriod:
          (qSyncPeriod - 1).start_slot
        else:
          GENESIS_SLOT + 1) - 1
      dependentRoot =
        if dependentSlot <= node.dag.finalizedHead.slot:
          node.dag.finalizedHead.blck.root  # No need to look up the actual root
        else:
          let bsi = node.dag.head.atSlot(dependentSlot)
          doAssert bsi.blck != nil, "Non-finalized block has `BlockRef`"
          bsi.blck.root
      optimistic = node.getShufflingOptimistic(dependentSlot, dependentRoot)

    if qSyncPeriod == headSyncPeriod:
      let res = withState(node.dag.headState):
        when consensusFork >= ConsensusFork.Altair:
          produceResponse(indexList,
                          forkyState.data.current_sync_committee.pubkeys.data,
                          forkyState.data.validators.asSeq)
        else:
          emptyResponse()
      return RestApiResponse.jsonResponseWOpt(res, optimistic)
    elif qSyncPeriod == (headSyncPeriod + 1):
      let res = withState(node.dag.headState):
        when consensusFork >= ConsensusFork.Altair:
          produceResponse(indexList,
                          forkyState.data.next_sync_committee.pubkeys.data,
                          forkyState.data.validators.asSeq)
        else:
          emptyResponse()
      return RestApiResponse.jsonResponseWOpt(res, optimistic)
    elif qSyncPeriod > headSyncPeriod:
      # The requested epoch may still be too far in the future.
      if not node.isSynced(node.dag.head) or not node.dag.head.executionValid:
        return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
      else:
        return RestApiResponse.jsonError(Http400, EpochFromFutureError)
    elif qSyncPeriod >= node.dag.cfg.ALTAIR_FORK_EPOCH.sync_committee_period:
      # The slot at the start of the sync committee period is likely to have a
      # state snapshot in the database, so we can restore the state relatively
      # cheaply:
      let earliestSlotInQSyncPeriod = max(
        node.dag.cfg.ALTAIR_FORK_EPOCH.start_slot,
        qSyncPeriod.start_slot)

      # TODO
      # The DAG can offer a short-cut for getting just the information we need
      # in order to compute the sync committee for the epoch. See the following
      # discussion for more details:
      # https://github.com/status-im/nimbus-eth2/pull/3133#pullrequestreview-817184693
      let bsi = node.dag.getBlockIdAtSlot(earliestSlotInQSyncPeriod).valueOr:
        return RestApiResponse.jsonError(Http404, StateNotFoundError)

      node.withStateForBlockSlotId(bsi):
        let res = withState(state):
          when consensusFork >= ConsensusFork.Altair:
            produceResponse(indexList,
                            forkyState.data.current_sync_committee.pubkeys.data,
                            forkyState.data.validators.asSeq)
          else:
            emptyResponse()
        return RestApiResponse.jsonResponseWOpt(res, optimistic)
    else:
      let res = emptyResponse()
      return RestApiResponse.jsonResponseWOpt(res, execOpt = Opt.some(false))

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceBlock
  router.api(MethodGet, "/eth/v1/validator/blocks/{slot}") do (
    slot: Slot, randao_reveal: Option[ValidatorSig],
    graffiti: Option[GraffitiBytes]) -> RestApiResponse:
    return RestApiResponse.jsonError(
      Http410, DeprecatedRemovalValidatorBlocksV1)

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV2
  router.api(MethodGet, "/eth/v2/validator/blocks/{slot}") do (
      slot: Slot, randao_reveal: Option[ValidatorSig],
      graffiti: Option[GraffitiBytes],
      skip_randao_verification: Option[string]) -> RestApiResponse:
    let
      contentType = preferredContentType(jsonMediaType, sszMediaType).valueOr:
        return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
    let message =
      block:
        let qslot = block:
          if slot.isErr():
            return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                              $slot.error())
          let res = slot.get()

          if res <= node.dag.finalizedHead.slot:
            return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                             "Slot already finalized")
          let
            wallTime = node.beaconClock.now() + MAXIMUM_GOSSIP_CLOCK_DISPARITY
          if res > wallTime.slotOrZero:
            return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                             "Slot cannot be in the future")
          res
        let qskip_randao_verification =
          if skip_randao_verification.isNone():
            false
          else:
            let res = skip_randao_verification.get()
            if res.isErr() or res.get() != "":
              return RestApiResponse.jsonError(
                Http400, InvalidSkipRandaoVerificationValue)
            true
        let qrandao =
          if randao_reveal.isNone():
            return RestApiResponse.jsonError(Http400, MissingRandaoRevealValue)
          else:
            let res = randao_reveal.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400,
                                               InvalidRandaoRevealValue,
                                               $res.error())
            res.get()
        let qgraffiti =
          if graffiti.isNone():
            defaultGraffitiBytes()
          else:
            let res = graffiti.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400,
                                               InvalidGraffitiBytesValue,
                                               $res.error())
            res.get()
        let qhead =
          block:
            let res = node.getSyncedHead(qslot)
            if res.isErr():
              return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                               $res.error())
            let tres = res.get()
            if not tres.executionValid:
              return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
            tres
        let
          proposer = node.dag.getProposer(qhead, qslot).valueOr:
            return RestApiResponse.jsonError(Http400, ProposerNotFoundError)

        if not node.verifyRandao(
            qslot, proposer, qrandao, qskip_randao_verification):
          return RestApiResponse.jsonError(Http400, InvalidRandaoRevealValue)

        let res = withConsensusFork(
            node.dag.cfg.consensusForkAtEpoch(qslot.epoch)):
          when consensusFork >= ConsensusFork.Bellatrix:
            await makeBeaconBlockForHeadAndSlot(
              consensusFork.ExecutionPayloadForSigning,
              node, qrandao, proposer, qgraffiti, qhead, qslot)
          else:
            return RestApiResponse.jsonError(Http400, InvalidSlotValueError)
        if res.isErr():
          return RestApiResponse.jsonError(Http400, res.error())
        res.get
    return
      withBlck(message.blck):
        let data =
          when consensusFork >= ConsensusFork.Deneb:
            let blobsBundle = message.blobsBundleOpt.get()
            deneb.BlockContents(
              `block`: forkyBlck,
              kzg_proofs: blobsBundle.proofs,
              blobs: blobsBundle.blobs)
          else:
            forkyBlck
        if contentType == sszMediaType:
          let headers = [("eth-consensus-version", consensusFork.toString())]
          RestApiResponse.sszResponse(data, headers)
        elif contentType == jsonMediaType:
          RestApiResponse.jsonResponseWVersion(data, consensusFork)
        else:
          raiseAssert "preferredContentType() returns invalid content type"

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceBlindedBlock
  # https://github.com/ethereum/beacon-APIs/blob/c097f1a62c9a12c30e8175a39f205f92d3b931a9/apis/validator/blinded_block.yaml
  router.api(MethodGet, "/eth/v1/validator/blinded_blocks/{slot}") do (
      slot: Slot, randao_reveal: Option[ValidatorSig],
      graffiti: Option[GraffitiBytes],
      skip_randao_verification: Option[string]) -> RestApiResponse:
    ## Requests a beacon node to produce a valid blinded block, which can then
    ## be signed by a validator. A blinded block is a block with only a
    ## transactions root, rather than a full transactions list.
    ##
    ## Metadata in the response indicates the type of block produced, and the
    ## supported types of block will be added to as forks progress.
    let contentType =
      block:
        let res = preferredContentType(jsonMediaType,
                                       sszMediaType)
        if res.isErr():
          return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
        res.get()
    let qslot = block:
      if slot.isErr():
        return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                          $slot.error())
      let res = slot.get()

      if res <= node.dag.finalizedHead.slot:
        return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                         "Slot already finalized")
      let
        wallTime = node.beaconClock.now() + MAXIMUM_GOSSIP_CLOCK_DISPARITY
      if res > wallTime.slotOrZero:
        return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                         "Slot cannot be in the future")
      res
    let qskip_randao_verification =
      if skip_randao_verification.isNone():
        false
      else:
        let res = skip_randao_verification.get()
        if res.isErr() or res.get() != "":
          return RestApiResponse.jsonError(Http400,
                                            InvalidSkipRandaoVerificationValue)
        true
    let qrandao =
      if randao_reveal.isNone():
        return RestApiResponse.jsonError(Http400, MissingRandaoRevealValue)
      else:
        let res = randao_reveal.get()
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidRandaoRevealValue,
                                           $res.error())
        res.get()
    let qgraffiti =
      if graffiti.isNone():
        defaultGraffitiBytes()
      else:
        let res = graffiti.get()
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidGraffitiBytesValue,
                                           $res.error())
        res.get()
    let qhead =
      block:
        let res = node.getSyncedHead(qslot)
        if res.isErr():
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                           $res.error())
        let tres = res.get()
        if not tres.executionValid:
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
        tres
    let proposer = node.dag.getProposer(qhead, qslot).valueOr:
      return RestApiResponse.jsonError(Http400, ProposerNotFoundError)

    if not node.verifyRandao(
        qslot, proposer, qrandao, qskip_randao_verification):
      return RestApiResponse.jsonError(Http400, InvalidRandaoRevealValue)

    template responseVersioned(
        response: untyped, contextFork: ConsensusFork): untyped =
      if contentType == sszMediaType:
        let headers = [("eth-consensus-version", contextFork.toString())]
        RestApiResponse.sszResponse(response, headers)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseWVersion(response, contextFork)
      else:
        RestApiResponse.jsonError(Http500, InvalidAcceptError)

    let
      payloadBuilderClient = node.getPayloadBuilderClient(
          proposer.distinctBase).valueOr:
        return RestApiResponse.jsonError(
          Http500, "Unable to initialize payload builder client: " & $error)
      contextFork = node.dag.cfg.consensusForkAtEpoch(node.currentSlot.epoch)

    withConsensusFork(contextFork):
      when consensusFork >= ConsensusFork.Capella:
        let res = await makeBlindedBeaconBlockForHeadAndSlot[
            consensusFork.BlindedBeaconBlock](
          node, payloadBuilderClient, qrandao,
          proposer, qgraffiti, qhead, qslot)
        if res.isErr():
          return RestApiResponse.jsonError(Http400, res.error())
        return responseVersioned(res.get().blindedBlckPart, contextFork)
      elif consensusFork >= ConsensusFork.Bellatrix:
        return RestApiResponse.jsonError(
          Http400, "Pre-Capella builder API unsupported")
      else:
        # Pre-Bellatrix, this endpoint will return a BeaconBlock
        let res = await makeBeaconBlockForHeadAndSlot(
          bellatrix.ExecutionPayloadForSigning, node, qrandao,
          proposer, qgraffiti, qhead, qslot)
        if res.isErr():
          return RestApiResponse.jsonError(Http400, res.error())
        withBlck(res.get().blck):
          return responseVersioned(forkyBlck, contextFork)

  func getMaybeBlindedHeaders(
      consensusFork: ConsensusFork,
      isBlinded: bool,
      executionValue: Opt[UInt256],
      consensusValue: Opt[UInt256]): HttpTable =
    var res = HttpTable.init()
    res.add("eth-consensus-version", consensusFork.toString())
    if isBlinded:
      res.add("eth-execution-payload-blinded", "true")
    else:
      res.add("eth-execution-payload-blinded", "false")
    if executionValue.isSome():
      res.add("eth-execution-payload-value", $(executionValue.get()))
    if consensusValue.isSome():
      res.add("eth-consensus-block-value", $(consensusValue.get()))
    res

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV3
  router.api(MethodGet, "/eth/v3/validator/blocks/{slot}") do (
      slot: Slot, randao_reveal: Option[ValidatorSig],
      graffiti: Option[GraffitiBytes],
      skip_randao_verification: Option[string]) -> RestApiResponse:
    let
      contentType = preferredContentType(jsonMediaType, sszMediaType).valueOr:
        return RestApiResponse.jsonError(Http406, ContentNotAcceptableError)
      qslot = block:
        if slot.isErr():
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           $slot.error())
        let res = slot.get()

        if res <= node.dag.finalizedHead.slot:
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           "Slot already finalized")
        let wallTime =
          node.beaconClock.now() + MAXIMUM_GOSSIP_CLOCK_DISPARITY
        if res > wallTime.slotOrZero:
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           "Slot cannot be in the future")
        res
      qskip_randao_verification =
        if skip_randao_verification.isNone():
          false
        else:
          let res = skip_randao_verification.get()
          if res.isErr() or res.get() != "":
            return RestApiResponse.jsonError(
              Http400, InvalidSkipRandaoVerificationValue)
          true
      qrandao =
        if randao_reveal.isNone():
          return RestApiResponse.jsonError(Http400,
                                           MissingRandaoRevealValue)
        else:
          let res = randao_reveal.get()
          if res.isErr():
            return RestApiResponse.jsonError(Http400,
                                             InvalidRandaoRevealValue,
                                             $res.error())
          res.get()
      qgraffiti =
        if graffiti.isNone():
          defaultGraffitiBytes()
        else:
          let res = graffiti.get()
          if res.isErr():
            return RestApiResponse.jsonError(Http400,
                                             InvalidGraffitiBytesValue,
                                             $res.error())
          res.get()
      qhead =
        block:
          let res = node.getSyncedHead(qslot)
          if res.isErr():
            return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                             $res.error())
          let tres = res.get()
          if not tres.executionValid:
            return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
          tres
      proposer = node.dag.getProposer(qhead, qslot).valueOr:
        return RestApiResponse.jsonError(Http400, ProposerNotFoundError)

    if not node.verifyRandao(
        qslot, proposer, qrandao, qskip_randao_verification):
      return RestApiResponse.jsonError(Http400, InvalidRandaoRevealValue)

    withConsensusFork(node.dag.cfg.consensusForkAtEpoch(qslot.epoch)):
      when consensusFork >= ConsensusFork.Capella:
        let
          message = (await node.makeMaybeBlindedBeaconBlockForHeadAndSlot(
              consensusFork, qrandao, qgraffiti, qhead, qslot)).valueOr:
            # HTTP 400 error is only for incorrect parameters.
            return RestApiResponse.jsonError(Http500, error)
          headers = consensusFork.getMaybeBlindedHeaders(
            message.blck.isBlinded,
            message.executionValue,
            message.consensusValue)

        if contentType == sszMediaType:
          if message.blck.isBlinded:
            RestApiResponse.sszResponse(message.blck.blindedData, headers)
          else:
            RestApiResponse.sszResponse(message.blck.data, headers)
        elif contentType == jsonMediaType:
          let forked =
            if message.blck.isBlinded:
              ForkedMaybeBlindedBeaconBlock.init(
                message.blck.blindedData,
                message.executionValue,
                message.consensusValue)
            else:
              ForkedMaybeBlindedBeaconBlock.init(
                message.blck.data,
                message.executionValue,
                message.consensusValue)
          RestApiResponse.jsonResponsePlain(forked, headers)
        else:
          raiseAssert "preferredContentType() returns invalid content type"
      else:
        when consensusFork >= ConsensusFork.Bellatrix:
          type PayloadType = consensusFork.ExecutionPayloadForSigning
        else:
          type PayloadType = bellatrix.ExecutionPayloadForSigning
        let
          message = (await PayloadType.makeBeaconBlockForHeadAndSlot(
              node, qrandao, proposer, qgraffiti, qhead, qslot)).valueOr:
            return RestApiResponse.jsonError(Http500, error)
          executionValue = Opt.some(UInt256(message.blockValue))
          consensusValue = Opt.none(UInt256)
          headers = consensusFork.getMaybeBlindedHeaders(
            isBlinded = false, executionValue, consensusValue)

        doAssert message.blck.kind == consensusFork
        template forkyBlck: untyped = message.blck.forky(consensusFork)
        if contentType == sszMediaType:
          RestApiResponse.sszResponse(forkyBlck, headers)
        elif contentType == jsonMediaType:
          let forked =
            when consensusFork >= ConsensusFork.Bellatrix:
              ForkedMaybeBlindedBeaconBlock.init(
                forkyBlck, executionValue, consensusValue)
            else:
              ForkedMaybeBlindedBeaconBlock.init(forkyBlck)
          RestApiResponse.jsonResponsePlain(forked, headers)
        else:
          raiseAssert "preferredContentType() returns invalid content type"

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData
  router.api(MethodGet, "/eth/v1/validator/attestation_data") do (
    slot: Option[Slot],
    committee_index: Option[CommitteeIndex]) -> RestApiResponse:
    let adata =
      block:
        let qslot =
          block:
            if slot.isNone():
              return RestApiResponse.jsonError(Http400, MissingSlotValueError)
            let res = slot.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                               $res.error())
            res.get()
        if qslot <= node.dag.finalizedHead.slot:
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           "Slot already finalized")
        let
          wallTime = node.beaconClock.now()
        if qslot > (wallTime + MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero:
          return RestApiResponse.jsonError(
            Http400, InvalidSlotValueError, "Slot cannot be in the future")
        if qslot + SLOTS_PER_EPOCH <
            (wallTime - MAXIMUM_GOSSIP_CLOCK_DISPARITY).slotOrZero:
          return RestApiResponse.jsonError(
            Http400, InvalidSlotValueError,
            "Slot cannot be more than an epoch in the past")

        let qindex =
          block:
            if committee_index.isNone():
              return RestApiResponse.jsonError(Http400,
                                               MissingCommitteeIndexValueError)
            let res = committee_index.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400,
                                               InvalidCommitteeIndexValueError,
                                               $res.error())
            res.get()
        let qhead =
          block:
            let res = node.getSyncedHead(qslot)
            if res.isErr():
              return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                               $res.error())
            let tres = res.get()
            if not tres.executionValid:
              return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
            tres
        let epochRef = node.dag.getEpochRef(qhead, qslot.epoch, true).valueOr:
          return RestApiResponse.jsonError(Http400, PrunedStateError, $error)
        makeAttestationData(epochRef, qhead.atSlot(qslot), qindex)
    return RestApiResponse.jsonResponse(adata)

  # https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestation
  router.api(MethodGet, "/eth/v1/validator/aggregate_attestation") do (
    attestation_data_root: Option[Eth2Digest],
    slot: Option[Slot]) -> RestApiResponse:
    let attestation =
      block:
        let qslot =
          block:
            if slot.isNone():
              return RestApiResponse.jsonError(Http400, MissingSlotValueError)
            let res = slot.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                               $res.error())
            res.get()
        let qroot =
          block:
            if attestation_data_root.isNone():
              return RestApiResponse.jsonError(Http400,
                                           MissingAttestationDataRootValueError)
            let res = attestation_data_root.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400,
                             InvalidAttestationDataRootValueError, $res.error())
            res.get()
        let res =
          node.attestationPool[].getAggregatedAttestation(qslot, qroot)
        if res.isNone():
          return RestApiResponse.jsonError(Http400,
                                          UnableToGetAggregatedAttestationError)
        res.get()
    return RestApiResponse.jsonResponse(attestation)

  # https://ethereum.github.io/beacon-APIs/#/Validator/publishAggregateAndProofs
  router.api(MethodPost, "/eth/v1/validator/aggregate_and_proofs") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let proofs =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[SignedAggregateAndProof], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidAggregateAndProofObjectError,
                                           $dres.error())
        dres.get()
    # Since our validation logic supports batch processing, we will submit all
    # aggregated attestations for validation.
    let pending =
      block:
        var res: seq[Future[SendResult]]
        for proof in proofs:
          res.add(node.router.routeSignedAggregateAndProof(proof))
        res
    await allFutures(pending)
    for future in pending:
      if future.completed():
        let res = future.read()
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           AggregateAndProofValidationError,
                                           $res.error())
      else:
        return RestApiResponse.jsonError(Http500,
               "Unexpected server failure, while sending aggregate and proof")
    return RestApiResponse.jsonMsgResponse(AggregateAndProofValidationSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet
  router.api(MethodPost,
             "/eth/v1/validator/beacon_committee_subscriptions") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let requests =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[RestCommitteeSubscription],
                              contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidSubscriptionRequestValueError,
                                           $dres.error())
        dres.get()

    if not node.isSynced(node.dag.head):
      return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)

    let
      wallSlot = node.beaconClock.now.slotOrZero
      wallEpoch = wallSlot.epoch
      head = node.dag.head

    var currentEpoch, nextEpoch: Opt[ShufflingRef]
    template getAndCacheShufflingRef(shufflingRefVar: var Opt[ShufflingRef],
                                     epoch: Epoch): ShufflingRef =
      if shufflingRefVar.isNone:
        shufflingRefVar = block:
          let tmp = node.dag.getShufflingRef(head, epoch, true).valueOr:
            return RestApiResponse.jsonError(Http400, PrunedStateError)
          Opt.some tmp

      shufflingRefVar.get

    for request in requests:
      if uint64(request.committee_index) >= uint64(MAX_COMMITTEES_PER_SLOT):
        return RestApiResponse.jsonError(Http400,
                                         InvalidCommitteeIndexValueError)
      if uint64(request.validator_index) >=
                  lenu64(getStateField(node.dag.headState, validators)):
        return RestApiResponse.jsonError(Http400,
                                         InvalidValidatorIndexValueError)
      if wallSlot > request.slot + 1:
        return RestApiResponse.jsonError(Http400, SlotFromThePastError)

      let
        epoch = request.slot.epoch
        shufflingRef =
          if epoch == wallEpoch:
            currentEpoch.getAndCacheShufflingRef(wallEpoch)
          elif epoch == wallEpoch + 1:
            nextEpoch.getAndCacheShufflingRef(wallEpoch + 1)
          else:
            return RestApiResponse.jsonError(Http400,
                                             SlotNotInNextWallSlotEpochError)

      let subnet_id = compute_subnet_for_attestation(
        get_committee_count_per_slot(shufflingRef), request.slot,
        request.committee_index)

      if not is_active_validator(
          getStateField(
            node.dag.headState, validators).item(request.validator_index),
          request.slot.epoch):
        return RestApiResponse.jsonError(Http400, ValidatorNotActive)

      node.consensusManager[].actionTracker.registerDuty(
        request.slot, subnet_id, request.validator_index,
        request.is_aggregator)

      let validator_pubkey =
        getStateField(node.dag.headState, validators).item(
          request.validator_index).pubkey

      node.validatorMonitor[].addAutoMonitor(
        validator_pubkey, ValidatorIndex(request.validator_index))

    return RestApiResponse.jsonMsgResponse(BeaconCommitteeSubscriptionSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Validator/prepareSyncCommitteeSubnets
  router.api(MethodPost,
             "/eth/v1/validator/sync_committee_subscriptions") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let subscriptions =
      block:
        var res: seq[RestSyncCommitteeSubscription]
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[RestSyncCommitteeSubscription],
                              contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                   InvalidSyncCommitteeSubscriptionRequestError)
        let subs = dres.get()
        for item in subs:
          if item.until_epoch > MaxEpoch:
            return RestApiResponse.jsonError(Http400, EpochOverflowValueError)
          if item.until_epoch < node.dag.cfg.ALTAIR_FORK_EPOCH:
            return RestApiResponse.jsonError(Http400,
                                             EpochFromTheIncorrectForkError)
          if uint64(item.validator_index) >=
            lenu64(getStateField(node.dag.headState, validators)):
            return RestApiResponse.jsonError(Http400,
                                             InvalidValidatorIndexValueError)
          res.add(item)
        res

    for item in subscriptions:
      let validator_pubkey =
        getStateField(node.dag.headState, validators).item(
          item.validator_index).pubkey

      node.consensusManager[].actionTracker.registerSyncDuty(
        validator_pubkey, item.until_epoch)

      node.validatorMonitor[].addAutoMonitor(
        validator_pubkey, ValidatorIndex(item.validator_index))

    return RestApiResponse.jsonMsgResponse(SyncCommitteeSubscriptionSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution
  router.api(MethodGet,
             "/eth/v1/validator/sync_committee_contribution") do (
    slot: Option[Slot], subcommittee_index: Option[SyncSubCommitteeIndex],
    beacon_block_root: Option[Eth2Digest]) -> RestApiResponse:
    let qslot = block:
      if slot.isNone():
        return RestApiResponse.jsonError(Http400, MissingSlotValueError)

      let res = slot.get()
      if res.isErr():
        return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                         $res.error())
      let rslot = res.get()
      if epoch(rslot) < node.dag.cfg.ALTAIR_FORK_EPOCH:
        return RestApiResponse.jsonError(Http400,
                                         SlotFromTheIncorrectForkError)
      rslot
    if qslot <= node.dag.finalizedHead.slot:
      return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                       "Slot already finalized")
    let qindex =
      if subcommittee_index.isNone():
        return RestApiResponse.jsonError(Http400,
                                         MissingSubCommitteeIndexValueError)
      else:
        let res = subcommittee_index.get()
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidSubCommitteeIndexValueError,
                                           $res.error())
        res.get()
    let qroot =
      if beacon_block_root.isNone():
        return RestApiResponse.jsonError(Http400,
                                         MissingBeaconBlockRootValueError)
      else:
        let res = beacon_block_root.get()
        if res.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidBeaconBlockRootValueError,
                                           $res.error())
        res.get()

    # Check if node is fully synced.
    block:
      let res = node.getSyncedHead(qslot)
      if res.isErr():
        return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError,
                                         $res.error())
      let tres = res.get()
      if not tres.executionValid:
        return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)

    var contribution = SyncCommitteeContribution()
    let
      blck = node.dag.getBlockRef(qroot).valueOr:
        return RestApiResponse.jsonError(Http404, BlockNotFoundError)
      res = node.syncCommitteeMsgPool[].produceContribution(
        qslot, blck.bid, qindex, contribution)
    if not(res):
      return RestApiResponse.jsonError(Http400, ProduceContributionError)
    return RestApiResponse.jsonResponse(contribution)

  # https://ethereum.github.io/beacon-APIs/#/Validator/publishContributionAndProofs
  router.api(MethodPost,
             "/eth/v1/validator/contribution_and_proofs") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let proofs =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let dres = decodeBody(seq[SignedContributionAndProof],
                              contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400,
                                           InvalidContributionAndProofMessageError)
        dres.get()

    let pending =
      block:
        var res: seq[Future[SendResult]]
        for proof in proofs:
          res.add(node.router.routeSignedContributionAndProof(proof, true))
        res

    let failures =
      block:
        var res: seq[RestIndexedErrorMessageItem]
        await allFutures(pending)
        for index, future in pending:
          if future.completed():
            let fres = future.read()
            if fres.isErr():
              let failure = RestIndexedErrorMessageItem(index: index,
                                                        message: $fres.error())
              res.add(failure)
          elif future.failed() or future.cancelled():
            # This is unexpected failure, so we log the error message.
            let exc = future.readError()
            let failure = RestIndexedErrorMessageItem(index: index,
                                                      message: $exc.msg)
            res.add(failure)
        res

    if len(failures) > 0:
      return RestApiResponse.jsonErrorList(Http400,
                                           ContributionAndProofValidationError,
                                           failures)
    else:
      return RestApiResponse.jsonMsgResponse(
        ContributionAndProofValidationSuccess
      )

  # https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/prepareBeaconProposer
  router.api(MethodPost,
             "/eth/v1/validator/prepare_beacon_proposer") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      body =
        block:
          if contentBody.isNone():
            return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
          let dres = decodeBody(seq[PrepareBeaconProposer], contentBody.get())
          if dres.isErr():
            return RestApiResponse.jsonError(Http400,
                                             InvalidPrepareBeaconProposerError)
          dres.get()
      currentEpoch = node.beaconClock.now.slotOrZero.epoch

    for proposerData in body:
      node.dynamicFeeRecipientsStore[].addMapping(
        proposerData.validator_index,
        proposerData.fee_recipient,
        currentEpoch)

    return RestApiResponse.response("", Http200, "text/plain")

  # https://ethereum.github.io/beacon-APIs/#/Validator/registerValidator
  # https://github.com/ethereum/beacon-APIs/blob/v2.3.0/apis/validator/register_validator.yaml
  router.api(MethodPost,
             "/eth/v1/validator/register_validator") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      body =
        block:
          if contentBody.isNone():
            return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
          let dres = decodeBody(seq[SignedValidatorRegistrationV1], contentBody.get())
          if dres.isErr():
            return RestApiResponse.jsonError(Http400,
                                             InvalidPrepareBeaconProposerError)
          dres.get()

    for signedValidatorRegistration in body:
      # Don't validate beyond syntactically, because
      # "requests containing currently inactive or unknown validator pubkeys
      # will be accepted, as they may become active at a later epoch". Along
      # these lines, even if it's adding a validator the BN already has as a
      # local validator, the keymanager API might remove that from the BN.
      node.externalBuilderRegistrations[signedValidatorRegistration.message.pubkey] =
        signedValidatorRegistration

    return RestApiResponse.response("", Http200, "text/plain")

  # https://ethereum.github.io/beacon-APIs/#/Validator/getLiveness
  router.api(MethodPost, "/eth/v1/validator/liveness/{epoch}") do (
    epoch: Epoch, contentBody: Option[ContentBody]) -> RestApiResponse:
    let
      qepoch =
        block:
          if epoch.isErr():
            return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                             $epoch.error())
          let
            res = epoch.get()
            wallEpoch = node.currentSlot().epoch()
            nextEpoch =
              if wallEpoch == FAR_FUTURE_EPOCH:
                wallEpoch
              else:
                wallEpoch + 1
            prevEpoch = get_previous_epoch(wallEpoch)
          if (res < prevEpoch) or (res > nextEpoch):
            return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                    "Requested epoch is more than one epoch from current epoch")

          if res < node.processor[].doppelgangerDetection.broadcastStartEpoch:
            # We can't accurately respond if we're not in sync and aren't
            # processing gossip
            return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
          res
      indexList =
        block:
          if contentBody.isNone():
            return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
          let dres = decodeBody(seq[RestValidatorIndex], contentBody.get())
          if dres.isErr():
            return RestApiResponse.jsonError(Http400,
                                             InvalidValidatorIndexValueError,
                                             $dres.error())
          var
            res: seq[ValidatorIndex]
            dupset: HashSet[ValidatorIndex]

          let items = dres.get()
          for item in items:
            let vres = item.toValidatorIndex()
            if vres.isErr():
              case vres.error()
              of ValidatorIndexError.TooHighValue:
                return RestApiResponse.jsonError(Http400,
                                                TooHighValidatorIndexValueError)
              of ValidatorIndexError.UnsupportedValue:
                return RestApiResponse.jsonError(Http500,
                                            UnsupportedValidatorIndexValueError)
            let index = vres.get()
            if index in dupset:
              return RestApiResponse.jsonError(Http400,
                                              DuplicateValidatorIndexArrayError)
            dupset.incl(index)
            res.add(index)
          if len(res) == 0:
            return RestApiResponse.jsonError(Http400,
                                             EmptyValidatorIndexArrayError)
          res
      response = indexList.mapIt(
        RestLivenessItem(
          index: it,
          is_live: node.attestationPool[].validatorSeenAtEpoch(qepoch, it)
        )
      )
    return RestApiResponse.jsonResponse(response)

  # https://github.com/ethereum/beacon-APIs/blob/f087fbf2764e657578a6c29bdf0261b36ee8db1e/apis/validator/beacon_committee_selections.yaml
  router.api(MethodPost, "/eth/v1/validator/beacon_committee_selections") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    # "Consensus clients need not support this endpoint and may return a 501."
    # https://github.com/ethereum/beacon-APIs/pull/224: "This endpoint need not
    # be implemented on the CL side. Once a validator client is aware of it and
    # able to use it when a feature flag is turned on, the intercepting
    # middleware can handle and swallow the request. I suggest a CL either
    # returns 501 Not Implemented [or] 400 Bad Request."
    return RestApiResponse.jsonError(
      Http501, AggregationSelectionNotImplemented)

  # https://github.com/ethereum/beacon-APIs/blob/f087fbf2764e657578a6c29bdf0261b36ee8db1e/apis/validator/sync_committee_selections.yaml
  router.api(MethodPost, "/eth/v1/validator/sync_committee_selections") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    # "Consensus clients need not support this endpoint and may return a 501."
    # https://github.com/ethereum/beacon-APIs/pull/224: "This endpoint need not
    # be implemented on the CL side. Once a validator client is aware of it and
    # able to use it when a feature flag is turned on, the intercepting
    # middleware can handle and swallow the request. I suggest a CL either
    # returns 501 Not Implemented [or] 400 Bad Request."
    return RestApiResponse.jsonError(
      Http501, AggregationSelectionNotImplemented)
