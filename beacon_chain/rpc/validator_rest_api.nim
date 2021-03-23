# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import
  std/[typetraits, strutils, deques, sets, options],
  stew/[results, base10],
  chronicles,
  nimcrypto/utils as ncrutils,
  ../beacon_node_common, ../networking/eth2_network,
  ../consensus_object_pools/[blockchain_dag, spec_cache, attestation_pool],
  ../gossip_processing/gossip_validation,
  ../validators/validator_duties,
  ../spec/[crypto, digest, datatypes, network],
  ../ssz/merkleization,
  ./eth2_json_rest_serialization, ./rest_utils

logScope: topics = "rest_validatorapi"

type
  AttesterDutyTuple* = tuple
    pubkey: ValidatorPubKey
    validator_index: ValidatorIndex
    committee_index: CommitteeIndex
    committee_length: uint64
    committees_at_slot: uint64
    validator_committee_index: ValidatorIndex
    slot: Slot

  ProposerDutyTuple* = tuple
    pubkey: ValidatorPubKey
    validator_index: ValidatorIndex
    slot: Slot

  CommitteeSubscriptionTuple* = tuple
    validator_index: ValidatorIndex
    committee_index: CommitteeIndex
    committees_at_slot: uint64
    slot: Slot
    is_aggregator: bool

proc installValidatorApiHandlers*(router: var RestRouter, node: BeaconNode) =
  # https://ethereum.github.io/eth2.0-APIs/#/Validator/getAttesterDuties
  router.api(MethodPost, "/api/eth/v1/validator/duties/attester/{epoch}") do (
    epoch: Epoch, contentBody: Option[ContentBody]) -> RestApiResponse:
    let indexList =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(seq[ValidatorIndex], contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode " &
            "list of validator indexes", $dres.error())
        dres.get()
    let qepoch =
      block:
        if epoch.isErr():
          return RestApiResponse.jsonError(Http400, "Incorrect epoch value",
                                           $epoch.error())
        let res = epoch.get()
        if res >= MaxEpoch:
          return RestApiResponse.jsonError(Http400, "Requesting epoch for " &
                                           "which slot would overflow")
        res
    let qhead =
      block:
        let res = node.getCurrentHead(qepoch)
        if res.isErr():
          if not(node.isSynced(node.chainDag.head)):
            return RestApiResponse.jsonError(Http503, "Beacon node is " &
              "currently syncing and not serving request on that endpoint")
          else:
            return RestApiResponse.jsonError(Http400,
                                             "Cound not find head for slot",
                                             $res.error())
        res.get()
    let droot =
      if qepoch >= Epoch(2):
        let bref = node.chainDag.getBlockByPreciseSlot(
          compute_start_slot_at_epoch(qepoch - 1) - 1
        )
        if isNil(bref):
          if not(node.isSynced(node.chainDag.head)):
            return RestApiResponse.jsonError(Http503, "Beacon node is " &
              "currently syncing and not serving request on that endpoint")
          else:
            return RestApiResponse.jsonError(Http400,
                                             "Cound not find slot data")
        bref.root
      else:
        node.chainDag.genesis.root
    let duties =
      block:
        var res: seq[AttesterDutyTuple]
        let epochRef = node.chainDag.getEpochRef(qhead, qepoch)
        let committees_per_slot = get_committee_count_per_slot(epochRef)
        for i in 0 ..< SLOTS_PER_EPOCH:
          let slot = compute_start_slot_at_epoch(qepoch) + i
          for committee_index in 0'u64 ..< committees_per_slot:
            let commitee = get_beacon_committee(
              epochRef, slot, CommitteeIndex(committee_index)
            )
            for index_in_committee, validator_index in commitee:
              if validator_index < ValidatorIndex(len(epochRef.validator_keys)):
                let validator_key = epochRef.validator_keys[validator_index]
                if validator_index in indexList:
                  res.add(
                    (
                      pubkey: validator_key,
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

  # https://ethereum.github.io/eth2.0-APIs/#/Validator/getProposerDuties
  router.api(MethodGet, "/api/eth/v1/validator/duties/proposer/{epoch}") do (
    epoch: Epoch) -> RestApiResponse:
    let qepoch =
      block:
        if epoch.isErr():
          return RestApiResponse.jsonError(Http400, "Incorrect epoch value",
                                           $epoch.error())
        let res = epoch.get()
        if res >= MaxEpoch:
          return RestApiResponse.jsonError(Http400, "Requesting epoch for " &
                                           "which slot would overflow")
        res
    let qhead =
      block:
        let res = node.getCurrentHead(qepoch)
        if res.isErr():
          if not(node.isSynced(node.chainDag.head)):
            return RestApiResponse.jsonError(Http503, "Beacon node is " &
              "currently syncing and not serving request on that endpoint")
          else:
            return RestApiResponse.jsonError(Http400,
                                             "Cound not find head for slot",
                                             $res.error())
        res.get()
    let droot =
      if qepoch >= Epoch(2):
        let bref = node.chainDag.getBlockByPreciseSlot(
          compute_start_slot_at_epoch(qepoch - 1) - 1
        )
        if isNil(bref):
          if not(node.isSynced(node.chainDag.head)):
            return RestApiResponse.jsonError(Http503, "Beacon node is " &
              "currently syncing and not serving request on that endpoint")
          else:
            return RestApiResponse.jsonError(Http400,
                                             "Cound not find slot data")
        bref.root
      else:
        node.chainDag.genesis.root
    let duties =
      block:
        var res: seq[ProposerDutyTuple]
        let epochRef = node.chainDag.getEpochRef(qhead, qepoch)
        for i in 0 ..< SLOTS_PER_EPOCH:
          if epochRef.beacon_proposers[i].isSome():
            let proposer = epochRef.beacon_proposers[i].get()
            res.add(
              (
                pubkey: proposer[1],
                validator_index: proposer[0],
                slot: compute_start_slot_at_epoch(qepoch) + i
              )
            )
        res
    return RestApiResponse.jsonResponseWRoot(duties, droot)

  # https://ethereum.github.io/eth2.0-APIs/#/Validator/produceBlock
  router.api(MethodGet, "/api/eth/v1/validator/blocks/{slot}") do (
    slot: Slot, randao_reveal: Option[ValidatorSig],
    graffiti: Option[GraffitiBytes]) -> RestApiResponse:
    let message =
      block:
        let qslot =
          block:
            if slot.isErr():
              return RestApiResponse.jsonError(Http400, "Incorrect slot value",
                                               $slot.error())
            slot.get()
        let qrandao =
          if randao_reveal.isNone():
            return RestApiResponse.jsonError(Http400,
                                             "Missing randao_reveal value")
          else:
            let res = randao_reveal.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400,
                                               "Incorrect randao_reveal value",
                                               $res.error())
            res.get()
        let qgraffiti =
          if graffiti.isNone():
            defaultGraffitiBytes()
          else:
            let res = graffiti.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400,
                                               "Incorrect graffiti bytes value",
                                               $res.error())
            res.get()
        let qhead =
          block:
            let res = node.getCurrentHead(qslot)
            if res.isErr():
              if not(node.isSynced(node.chainDag.head)):
                return RestApiResponse.jsonError(Http503, "Beacon node is " &
                  "currently syncing and not serving request on that endpoint")
              else:
                return RestApiResponse.jsonError(Http400,
                                                 "Cound not find head for slot",
                                                 $res.error())
            res.get()
        let proposer = node.chainDag.getProposer(qhead, qslot)
        if proposer.isNone():
          return RestApiResponse.jsonError(Http400,
                                           "Could not retrieve block for slot")
        let res = makeBeaconBlockForHeadAndSlot(
          node, qrandao, proposer.get()[0], qgraffiti, qhead, qslot)
        if res.isNone():
          return RestApiResponse.jsonError(Http400,
                                           "Could not make block for slot")
        res.get()
    return RestApiResponse.jsonResponse(message)

  # https://ethereum.github.io/eth2.0-APIs/#/Validator/produceAttestationData
  router.api(MethodGet, "/api/eth/v1/validator/attestation_data") do (
    slot: Option[Slot],
    committee_index: Option[CommitteeIndex]) -> RestApiResponse:
    let adata =
      block:
        let qslot =
          block:
            if slot.isNone():
              return RestApiResponse.jsonError(Http400, "Missing slot value")
            let res = slot.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400, "Incorrect slot value",
                                               $res.error())
            res.get()
        let qindex =
          block:
            if committee_index.isNone():
              return RestApiResponse.jsonError(Http400,
                                               "Missing committee_index value")
            let res = committee_index.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400, "Incorrect " &
                                               "committee_index value",
                                               $res.error())
            res.get()
        let qhead =
          block:
            let res = node.getCurrentHead(qslot)
            if res.isErr():
              if not(node.isSynced(node.chainDag.head)):
                return RestApiResponse.jsonError(Http503, "Beacon node is " &
                  "currently syncing and not serving request on that endpoint")
              else:
                return RestApiResponse.jsonError(Http400,
                                                 "Cound not find head for slot",
                                                 $res.error())
            res.get()
        let epochRef = node.chainDag.getEpochRef(qhead, qslot.epoch)
        makeAttestationData(epochRef, qhead.atSlot(qslot), qindex)
    return RestApiResponse.jsonResponse(adata)

  # https://ethereum.github.io/eth2.0-APIs/#/Validator/getAggregatedAttestation
  router.api(MethodGet, "/api/eth/v1/validator/aggregate_attestation") do (
    attestation_data_root: Option[Eth2Digest],
    slot: Option[Slot]) -> RestApiResponse:
    let attestation =
      block:
        let qslot =
          block:
            if slot.isNone():
              return RestApiResponse.jsonError(Http400, "Missing slot value")
            let res = slot.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400, "Incorrect slot value",
                                               $res.error())
            res.get()
        let qroot =
          block:
            if attestation_data_root.isNone():
              return RestApiResponse.jsonError(Http400, "Missing " &
                                               "attestation_data_root value")
            let res = attestation_data_root.get()
            if res.isErr():
              return RestApiResponse.jsonError(Http400, "Incorrect " &
                                               "attestation_data_root value",
                                               $res.error())
            res.get()
        let res = node.attestationPool[].getAggregatedAttestation(qslot, qroot)
        if res.isNone():
          return RestApiResponse.jsonError(Http400, "Could not retrieve an " &
                                           "aggregated attestation")
        res.get()
    return RestApiResponse.jsonResponse(attestation)

  # https://ethereum.github.io/eth2.0-APIs/#/Validator/publishAggregateAndProofs
  router.api(MethodPost, "/api/eth/v1/validator/aggregate_and_proofs") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    let payload =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(SignedAggregateAndProof, contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode " &
            "SignedAggregateAndProof object", $dres.error())
        dres.get()

    let wallTime = node.processor.getWallTime()
    let res = node.attestationPool[].validateAggregate(payload, wallTime)
    if res.isErr():
      return RestApiResponse.jsonError(Http400, "Aggregate and proofs " &
        "verification failed", $res.error())
    node.network.broadcast(node.topicAggregateAndProofs, payload)
    return RestApiResponse.jsonError(Http200,
                                     "Aggregate and proofs was broadcasted")

  # https://ethereum.github.io/eth2.0-APIs/#/Validator/prepareBeaconCommitteeSubnet
  router.api(MethodPost,
             "/api/eth/v1/validator/beacon_committee_subscriptions") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:
    # TODO: This call could not be finished because more complex peer manager
    # is needed.
    let requests =
      block:
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, "Empty request's body")
        let dres = decodeBody(seq[CommitteeSubscriptionTuple],
                              contentBody.get())
        if dres.isErr():
          return RestApiResponse.jsonError(Http400, "Unable to decode " &
            "subscription request(s)")
        dres.get()
    if not(node.isSynced(node.chainDag.head)):
      return RestApiResponse.jsonError(Http503, "Beacon node is " &
        "currently syncing and not serving request on that endpoint")

    for request in requests:
      if uint64(request.committee_index) >= uint64(ATTESTATION_SUBNET_COUNT):
        return RestApiResponse.jsonError(Http400, "Invalid committee_index " &
                                         "value")
      let validator_pubkey =
        block:
          let idx = request.validator_index
          if uint64(idx) >=
                           lenu64(node.chainDag.headState.data.data.validators):
            return RestApiResponse.jsonError(Http400,
                                             "Invalid validator_index value")
          node.chainDag.headState.data.data.validators[idx].pubkey

      let wallSlot = node.beaconClock.now.slotOrZero
      if wallSlot > request.slot + 1:
        return RestApiResponse.jsonError(Http400, "Past slot requested")
      let epoch = request.slot.epoch
      if epoch >= wallSlot.epoch and epoch - wallSlot.epoch > 1:
        return RestApiResponse.jsonError(Http400, "Slot requested not in " &
          "next wall-slot epoch")
      let head =
        block:
          let res = node.getCurrentHead(epoch)
          if res.isErr():
            return RestApiResponse.jsonError(Http400, "Unable to obtain head",
                                             $res.error())
          res.get()
      let epochRef = node.chainDag.getEpochRef(head, epoch)
      let subnet = uint8(compute_subnet_for_attestation(
        get_committee_count_per_slot(epochRef), request.slot,
        request.committee_index)
      )
    return RestApiResponse.jsonError(Http500, "Not implemented yet")
