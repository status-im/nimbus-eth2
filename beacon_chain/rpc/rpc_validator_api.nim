# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  std/tables,

  # Nimble packages
  stew/objects,
  json_rpc/servers/httpserver,
  chronicles,

  # Local modules
  ../spec/[forks, helpers, network, signatures],
  ../spec/datatypes/phase0,
  ../spec/eth2_apis/rpc_types,
  ../consensus_object_pools/[blockchain_dag, spec_cache, attestation_pool],
  ../beacon_node,
  ../validators/validator_duties,
  ../networking/eth2_network,
  ./rpc_utils

logScope: topics = "valapi"

type
  RpcServer* = RpcHttpServer

proc installValidatorApiHandlers*(rpcServer: RpcServer, node: BeaconNode) {.
    raises: [Defect, CatchableError].} =
  rpcServer.rpc("get_v1_validator_block") do (
      slot: Slot, graffiti: GraffitiBytes, randao_reveal: ValidatorSig) -> phase0.BeaconBlock:
    debug "get_v1_validator_block", slot = slot
    let head = node.doChecksAndGetCurrentHead(slot)
    let proposer = node.dag.getProposer(head, slot)
    if proposer.isNone():
      raise newException(CatchableError,
                         "could not retrieve block for slot: " & $slot)
    let message = await makeBeaconBlockForHeadAndSlot(
      node, randao_reveal, proposer.get(), graffiti, head, slot)
    if message.isErr():
      raise newException(CatchableError,
                         "could not retrieve block for slot: " & $slot)
    let blck = message.get()
    case blck.kind
    of BeaconBlockFork.Phase0:
      return blck.phase0Data
    else:
      raiseNoAltairSupport()

  rpcServer.rpc("get_v1_validator_attestation_data") do (
      slot: Slot, committee_index: CommitteeIndex) -> AttestationData:
    debug "get_v1_validator_attestation_data", slot = slot
    let
      head = node.doChecksAndGetCurrentHead(slot)
      epochRef = block:
        let tmp = node.dag.getEpochRef(head, slot.epoch, true)
        if isErr(tmp):
          raise (ref CatchableError)(msg: "Trying to access pruned state")
        tmp.get()

    return makeAttestationData(epochRef, head.atSlot(slot), committee_index)

  rpcServer.rpc("get_v1_validator_aggregate_attestation") do (
      slot: Slot, attestation_data_root: Eth2Digest)-> Attestation:
    debug "get_v1_validator_aggregate_attestation"
    let res = node.attestationPool[].getAggregatedAttestation(slot, attestation_data_root)
    if res.isSome:
      return res.get
    raise newException(CatchableError, "Could not retrieve an aggregated attestation")

  rpcServer.rpc("post_v1_validator_aggregate_and_proofs") do (
      payload: SignedAggregateAndProof) -> bool:
    debug "post_v1_validator_aggregate_and_proofs"
    return (await node.sendAggregateAndProof(payload)).isOk()

  rpcServer.rpc("get_v1_validator_duties_attester") do (
      epoch: Epoch, public_keys: seq[ValidatorPubKey]) -> seq[RpcAttesterDuties]:
    debug "get_v1_validator_duties_attester", epoch = epoch
    let
      head = node.doChecksAndGetCurrentHead(epoch)
      epochRef = block:
        let tmp = node.dag.getEpochRef(head, epoch, true)
        if isErr(tmp):
          raise (ref CatchableError)(msg: "Trying to access pruned state")
        tmp.get()

    let
      committees_per_slot = get_committee_count_per_slot(epochRef)
    for i in 0 ..< SLOTS_PER_EPOCH:
      let slot = compute_start_slot_at_epoch(epoch) + i
      for committee_index in 0'u64..<committees_per_slot:
        let committee = get_beacon_committee(
          epochRef, slot, committee_index.CommitteeIndex)
        for index_in_committee, validatorIdx in committee:
          let curr_val_pubkey = epochRef.validatorKey(validatorIdx)
          if curr_val_pubkey.isSome():
            if public_keys.findIt(it == curr_val_pubkey.get().toPubKey()) != -1:
              result.add((public_key: curr_val_pubkey.get().toPubKey(),
                          validator_index: validatorIdx,
                          committee_index: committee_index.CommitteeIndex,
                          committee_length: committee.lenu64,
                          validator_committee_index: index_in_committee.uint64,
                          slot: slot))

  rpcServer.rpc("get_v1_validator_duties_proposer") do (
      epoch: Epoch) -> seq[RpcValidatorDuties]:
    debug "get_v1_validator_duties_proposer", epoch = epoch
    let
      head = node.doChecksAndGetCurrentHead(epoch)
      epochRef = block:
        let tmp = node.dag.getEpochRef(head, epoch, true)
        if isErr(tmp):
          raise (ref CatchableError)(msg: "Trying to access pruned state")
        tmp.get()

    for i, bp in epochRef.beacon_proposers:
      if bp.isSome():
        result.add((public_key: epochRef.validatorKey(bp.get).get().toPubKey,
                    validator_index: bp.get(),
                    slot: compute_start_slot_at_epoch(epoch) + i))

  rpcServer.rpc("post_v1_validator_beacon_committee_subscriptions") do (
      committee_index: CommitteeIndex, slot: Slot, aggregator: bool,
      validator_pubkey: ValidatorPubKey, slot_signature: ValidatorSig) -> bool:
    debug "post_v1_validator_beacon_committee_subscriptions",
      committee_index, slot
    if committee_index.uint64 >= MAX_COMMITTEES_PER_SLOT.uint64:
      raise newException(CatchableError,
        "Invalid committee index")

    if node.syncManager.inProgress:
      raise newException(CatchableError,
        "Beacon node is currently syncing and not serving request on that endpoint")

    let wallSlot = node.beaconClock.now.slotOrZero
    if wallSlot > slot + 1:
      raise newException(CatchableError,
        "Past slot requested")

    let epoch = slot.epoch
    if epoch >= wallSlot.epoch and epoch - wallSlot.epoch > 1:
      raise newException(CatchableError,
        "Slot requested not in current or next wall-slot epoch")

    if not verify_slot_signature(
        getStateField(node.dag.headState.data, fork),
        getStateField(node.dag.headState.data, genesis_validators_root),
        slot, validator_pubkey, slot_signature):
      raise newException(CatchableError,
        "Invalid slot signature")

    let
      head = node.doChecksAndGetCurrentHead(epoch)
      epochRef = block:
        let tmp = node.dag.getEpochRef(head, epoch, true)
        if isErr(tmp):
          raise (ref CatchableError)(msg: "Trying to access pruned state")
        tmp.get()
    let
      subnet_id = compute_subnet_for_attestation(
        get_committee_count_per_slot(epochRef), slot, committee_index)

    # The validator index here is invalid, but since JSON-RPC is on its way
    # to deprecation, this is fine
    node.registerDuty(
      slot, subnet_id, 0.ValidatorIndex,
       is_aggregator(epochRef, slot, committee_index, slot_signature))
