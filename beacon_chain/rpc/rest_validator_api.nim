# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import std/[typetraits, strutils, sets]
import stew/[results, base10], chronicles,
       nimcrypto/utils as ncrutils
import "."/rest_utils,
       ".."/[beacon_chain_db, beacon_node],
       ".."/networking/eth2_network,
       ".."/consensus_object_pools/[blockchain_dag, spec_cache,
                                    attestation_pool, sync_committee_msg_pool],
       ".."/validators/validator_duties,
       ".."/spec/[beaconstate, forks, network],
       ".."/spec/datatypes/[phase0, altair]

export rest_utils

logScope: topics = "rest_validatorapi"

proc installValidatorApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties
  router.api(MethodPost, "/api/eth/v1/validator/duties/attester/{epoch}") do (
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
        let res = epoch.get()
        if res > MaxEpoch:
          return RestApiResponse.jsonError(Http400, EpochOverflowValueError)
        res
    let qhead =
      block:
        let res = node.getCurrentHead(qepoch)
        if res.isErr():
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
        res.get()
    let droot =
      if qepoch >= Epoch(2):
        qhead.atSlot(compute_start_slot_at_epoch(qepoch - 1) - 1).blck.root
      else:
        node.dag.genesis.root
    let duties =
      block:
        var res: seq[RestAttesterDuty]
        let epochRef = node.dag.getEpochRef(qhead, qepoch)
        let committees_per_slot = get_committee_count_per_slot(epochRef)
        for i in 0 ..< SLOTS_PER_EPOCH:
          let slot = compute_start_slot_at_epoch(qepoch) + i
          for committee_index in 0'u64 ..< committees_per_slot:
            let commitee = get_beacon_committee(
              epochRef, slot, CommitteeIndex(committee_index)
            )
            for index_in_committee, validator_index in commitee:
              if validator_index in indexList:
                let validator_key = epochRef.validatorKey(validator_index)
                if validator_key.isSome():
                  res.add(
                    RestAttesterDuty(
                      pubkey: validator_key.get().toPubKey(),
                      validator_index: validator_index,
                      committee_index: CommitteeIndex(committee_index),
                      committee_length: lenu64(commitee),
                      committees_at_slot: committees_per_slot,
                      validator_committee_index:
                        ValidatorIndex(index_in_committee),
                      slot: slot
                    )
                  )
        res
    return RestApiResponse.jsonResponseWRoot(duties, droot)

  # https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties
  router.api(MethodGet, "/api/eth/v1/validator/duties/proposer/{epoch}") do (
    epoch: Epoch) -> RestApiResponse:
    let qepoch =
      block:
        if epoch.isErr():
          return RestApiResponse.jsonError(Http400, InvalidEpochValueError,
                                           $epoch.error())
        let res = epoch.get()
        if res > MaxEpoch:
          return RestApiResponse.jsonError(Http400, EpochOverflowValueError)
        res
    let qhead =
      block:
        let res = node.getCurrentHead(qepoch)
        if res.isErr():
          return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
        res.get()
    let droot =
      if qepoch >= Epoch(2):
        qhead.atSlot(compute_start_slot_at_epoch(qepoch - 1) - 1).blck.root
      else:
        node.dag.genesis.root
    let duties =
      block:
        var res: seq[RestProposerDuty]
        let epochRef = node.dag.getEpochRef(qhead, qepoch)
        for i, bp in epochRef.beacon_proposers:
          if i == 0 and qepoch == 0:
            # Fix for https://github.com/status-im/nimbus-eth2/issues/2488
            # Slot(0) at Epoch(0) do not have a proposer.
            continue

          if bp.isSome():
            res.add(
              RestProposerDuty(
                pubkey: epochRef.validatorKey(bp.get()).get().toPubKey(),
                validator_index: bp.get(),
                slot: compute_start_slot_at_epoch(qepoch) + i
              )
            )
        res
    return RestApiResponse.jsonResponseWRoot(duties, droot)

  router.api(MethodPost, "/api/eth/v1/validator/duties/sync/{epoch}") do (
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
          # (we won't bother to validate it agains a more recent state).
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

    if qSyncPeriod == headSyncPeriod:
      let res = withState(node.dag.headState.data):
        when stateFork >= BeaconStateFork.Altair:
          produceResponse(indexList,
                          state.data.current_sync_committee.pubkeys.data,
                          state.data.validators.asSeq)
        else:
          emptyResponse()
      return RestApiResponse.jsonResponse(res)
    elif qSyncPeriod == (headSyncPeriod + 1):
      let res = withState(node.dag.headState.data):
        when stateFork >= BeaconStateFork.Altair:
          produceResponse(indexList,
                          state.data.next_sync_committee.pubkeys.data,
                          state.data.validators.asSeq)
        else:
          emptyResponse()
      return RestApiResponse.jsonResponse(res)
    elif qSyncPeriod > headSyncPeriod:
      # The requested epoch may still be too far in the future.
      if not(node.isSynced(node.dag.head)):
        return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
      else:
        return RestApiResponse.jsonError(Http400, EpochFromFutureError)
    else:
      # The slot at the start of the sync committee period is likely to have a
      # state snapshot in the database, so we can restore the state relatively
      # cheaply:
      let earliestSlotInQSyncPeriod =
        Slot(qSyncPeriod * SLOTS_PER_SYNC_COMMITTEE_PERIOD)

      # TODO
      # The DAG can offer a short-cut for getting just the information we need
      # in order to compute the sync committee for the epoch. See the following
      # discussion for more details:
      # https://github.com/status-im/nimbus-eth2/pull/3133#pullrequestreview-817184693
      node.withStateForBlockSlot(node.dag.getBlockBySlot(earliestSlotInQSyncPeriod)):
        let res = withState(stateData().data):
          when stateFork >= BeaconStateFork.Altair:
            produceResponse(indexList,
                              state.data.current_sync_committee.pubkeys.data,
                            state.data.validators.asSeq)
          else:
            emptyResponse()
        return RestApiResponse.jsonResponse(res)

    return RestApiResponse.jsonError(Http404, StateNotFoundError)

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceBlock
  router.api(MethodGet, "/api/eth/v1/validator/blocks/{slot}") do (
    slot: Slot, randao_reveal: Option[ValidatorSig],
    graffiti: Option[GraffitiBytes]) -> RestApiResponse:
    let message =
      block:
        let qslot =
          block:
            if slot.isErr():
              return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                               $slot.error())
            slot.get()
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
                                               InvalidGraffitiBytesValye,
                                               $res.error())
            res.get()
        let qhead =
          block:
            let res = node.getCurrentHead(qslot)
            if res.isErr():
              if not(node.isSynced(node.dag.head)):
                return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
              else:
                return RestApiResponse.jsonError(Http400, NoHeadForSlotError,
                                                 $res.error())
            res.get()
        let proposer = node.dag.getProposer(qhead, qslot)
        if proposer.isNone():
          return RestApiResponse.jsonError(Http400, ProposerNotFoundError)
        let res = await makeBeaconBlockForHeadAndSlot(
          node, qrandao, proposer.get(), qgraffiti, qhead, qslot)
        if res.isErr():
          return RestApiResponse.jsonError(Http400, res.error())
        res.get()
    return
      case message.kind
      of BeaconBlockFork.Phase0:
        RestApiResponse.jsonResponse(message.phase0Data)
      else:
        RestApiResponse.jsonError(Http400,
                                  "Unable to produce block for altair fork")

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV2
  router.api(MethodGet, "/api/eth/v2/validator/blocks/{slot}") do (
    slot: Slot, randao_reveal: Option[ValidatorSig],
    graffiti: Option[GraffitiBytes]) -> RestApiResponse:
    let message =
      block:
        let qslot =
          block:
            if slot.isErr():
              return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                               $slot.error())
            slot.get()
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
                                               InvalidGraffitiBytesValye,
                                               $res.error())
            res.get()
        let qhead =
          block:
            let res = node.getCurrentHead(qslot)
            if res.isErr():
              if not(node.isSynced(node.dag.head)):
                return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
              else:
                return RestApiResponse.jsonError(Http400, NoHeadForSlotError,
                                                 $res.error())
            res.get()
        let proposer = node.dag.getProposer(qhead, qslot)
        if proposer.isNone():
          return RestApiResponse.jsonError(Http400, ProposerNotFoundError)
        let res = await makeBeaconBlockForHeadAndSlot(
          node, qrandao, proposer.get(), qgraffiti, qhead, qslot)
        if res.isErr():
          return RestApiResponse.jsonError(Http400, res.error())
        res.get()
    return RestApiResponse.jsonResponsePlain(message)

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData
  router.api(MethodGet, "/api/eth/v1/validator/attestation_data") do (
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
            let res = node.getCurrentHead(qslot)
            if res.isErr():
              return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)
            res.get()
        let epochRef = node.dag.getEpochRef(qhead, qslot.epoch)
        makeAttestationData(epochRef, qhead.atSlot(qslot), qindex)
    return RestApiResponse.jsonResponse(adata)

  # https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestation
  router.api(MethodGet, "/api/eth/v1/validator/aggregate_attestation") do (
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
        let res = node.attestationPool[].getAggregatedAttestation(qslot, qroot)
        if res.isNone():
          return RestApiResponse.jsonError(Http400,
                                          UnableToGetAggregatedAttestationError)
        res.get()
    return RestApiResponse.jsonResponse(attestation)

  # https://ethereum.github.io/beacon-APIs/#/Validator/publishAggregateAndProofs
  router.api(MethodPost, "/api/eth/v1/validator/aggregate_and_proofs") do (
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
    var pending =
      block:
        var res: seq[Future[SendResult]]
        for proof in proofs:
          res.add(node.sendAggregateAndProof(proof))
        res
    await allFutures(pending)
    for future in pending:
      if future.done():
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
             "/api/eth/v1/validator/beacon_committee_subscriptions") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    # TODO (cheatfate): This call could not be finished because more complex
    # peer manager implementation needed.
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
    if not(node.isSynced(node.dag.head)):
      return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)

    let
      wallSlot = node.beaconClock.now.slotOrZero
      wallEpoch = wallSlot.epoch
      head = node.dag.head

    var currentEpoch, nextEpoch: Option[EpochRef]
    template getAndCacheEpochRef(epochRefVar: var Option[EpochRef],
                                 epoch: Epoch): EpochRef =
      if epochRefVar.isNone:
        epochRefVar = some node.dag.getEpochRef(head, epoch)
      epochRefVar.get

    for request in requests:
      if uint64(request.committee_index) >= uint64(MAX_COMMITTEES_PER_SLOT):
        return RestApiResponse.jsonError(Http400,
                                         InvalidCommitteeIndexValueError)
      if uint64(request.validator_index) >=
                  lenu64(getStateField(node.dag.headState.data, validators)):
        return RestApiResponse.jsonError(Http400,
                                         InvalidValidatorIndexValueError)
      if wallSlot > request.slot + 1:
        return RestApiResponse.jsonError(Http400, SlotFromThePastError)

      let epoch = request.slot.epoch
      let epochRef = if epoch == wallEpoch:
        currentEpoch.getAndCacheEpochRef(wallEpoch)
      elif epoch == wallEpoch + 1:
        nextEpoch.getAndCacheEpochRef(wallEpoch + 1)
      else:
        return RestApiResponse.jsonError(Http400,
                                         SlotNotInNextWallSlotEpochError)

      let subnet_id = compute_subnet_for_attestation(
        get_committee_count_per_slot(epochRef), request.slot,
        request.committee_index)

      node.registerDuty(
        request.slot, subnet_id, request.validator_index,
        request.is_aggregator)

      let validator_pubkey = getStateField(
        node.dag.headState.data, validators).asSeq()[request.validator_index].pubkey

      node.validatorMonitor[].addAutoMonitor(
        validator_pubkey, ValidatorIndex(request.validator_index))

    return RestApiResponse.jsonMsgResponse(BeaconCommitteeSubscriptionSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Validator/prepareSyncCommitteeSubnets
  router.api(MethodPost,
             "/api/eth/v1/validator/sync_committee_subscriptions") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let subscriptions =
      block:
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
             lenu64(getStateField(node.dag.headState.data, validators)):
            return RestApiResponse.jsonError(Http400,
                                             InvalidValidatorIndexValueError)
          let validator_pubkey = getStateField(
            node.dag.headState.data, validators).asSeq()[item.validator_index].pubkey

          node.validatorMonitor[].addAutoMonitor(
            validator_pubkey, ValidatorIndex(item.validator_index))

        subs

    warn "Sync committee subscription request served, but not implemented"
    return RestApiResponse.jsonMsgResponse(SyncCommitteeSubscriptionSuccess)

  # https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution
  router.api(MethodGet,
             "/api/eth/v1/validator/sync_committee_contribution") do (
    slot: Option[Slot], subcommittee_index: Option[uint64],
    beacon_block_root: Option[Eth2Digest]) -> RestApiResponse:
    # We doing this check to avoid any confusion in future.
    static: doAssert(SYNC_COMMITTEE_SUBNET_COUNT <= high(uint8))
    let qslot =
      if slot.isNone():
        return RestApiResponse.jsonError(Http400, MissingSlotValueError)
      else:
        let res = slot.get()
        if res.isErr():
          return RestApiResponse.jsonError(Http400, InvalidSlotValueError,
                                           $res.error())
        let rslot = res.get()
        if epoch(rslot) < node.dag.cfg.ALTAIR_FORK_EPOCH:
          return RestApiResponse.jsonError(Http400,
                                           SlotFromTheIncorrectForkError)
        rslot
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
        let value = res.get().validateSyncCommitteeIndexOr:
          return RestApiResponse.jsonError(Http400,
                                           InvalidSubCommitteeIndexValueError,
                                           "subcommittee_index exceeds " &
                                           "maximum allowed value")
        value
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
    let sres = node.getCurrentHead(qslot)
    if sres.isErr():
      return RestApiResponse.jsonError(Http503, BeaconNodeInSyncError)

    var contribution = SyncCommitteeContribution()
    let res = node.syncCommitteeMsgPool[].produceContribution(
      qslot, qroot, qindex, contribution)
    if not(res):
      return RestApiResponse.jsonError(Http400, ProduceContributionError)
    return RestApiResponse.jsonResponse(contribution)

  # https://ethereum.github.io/beacon-APIs/#/Validator/publishContributionAndProofs
  router.api(MethodPost,
             "/api/eth/v1/validator/contribution_and_proofs") do (
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
          res.add(node.sendSyncCommitteeContribution(proof, true))
        res

    let failures =
      block:
        var res: seq[RestAttestationsFailure]
        await allFutures(pending)
        for index, future in pending.pairs():
          if future.done():
            let fres = future.read()
            if fres.isErr():
              let failure = RestAttestationsFailure(index: uint64(index),
                                                    message: $fres.error())
              res.add(failure)
          elif future.failed() or future.cancelled():
            # This is unexpected failure, so we log the error message.
            let exc = future.readError()
            let failure = RestAttestationsFailure(index: uint64(index),
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

  router.redirect(
    MethodPost,
    "/eth/v1/validator/duties/attester/{epoch}",
    "/api/eth/v1/validator/duties/attester/{epoch}"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/validator/duties/proposer/{epoch}",
    "/api/eth/v1/validator/duties/proposer/{epoch}"
  )
  router.redirect(
    MethodPost,
    "/eth/v1/validator/duties/sync/{epoch}",
    "/api/eth/v1/validator/duties/sync/{epoch}"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/validator/blocks/{slot}",
    "/api/eth/v1/validator/blocks/{slot}"
  )
  router.redirect(
    MethodGet,
    "/eth/v2/validator/blocks/{slot}",
    "/api/eth/v2/validator/blocks/{slot}"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/validator/attestation_data",
    "/api/eth/v1/validator/attestation_data"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/validator/aggregate_attestation",
    "/api/eth/v1/validator/aggregate_attestation"
  )
  router.redirect(
    MethodPost,
    "/eth/v1/validator/aggregate_and_proofs",
    "/api/eth/v1/validator/aggregate_and_proofs"
  )
  router.redirect(
    MethodPost,
    "/eth/v1/validator/beacon_committee_subscriptions",
    "/api/eth/v1/validator/beacon_committee_subscriptions"
  )
  router.redirect(
    MethodPost,
    "/eth/v1/validator/sync_committee_subscriptions",
    "/api/eth/v1/validator/sync_committee_subscriptions"
  )
  router.redirect(
    MethodGet,
    "/eth/v1/validator/sync_committee_contribution",
    "/api/eth/v1/validator/sync_committee_contribution"
  )
  router.redirect(
    MethodPost,
    "/eth/v1/validator/contribution_and_proofs",
    "/api/eth/v1/validator/contribution_and_proofs"
  )
