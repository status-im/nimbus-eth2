# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  tables, strutils, parseutils, sequtils,

  # Nimble packages
  stew/[byteutils, objects],
  chronos, metrics, json_rpc/[rpcserver, jsonmarshal],
  chronicles,

  # Local modules
  spec/[datatypes, digest, crypto, validator, beaconstate, helpers],
  block_pool, ssz/merkleization,
  beacon_node_common, beacon_node_types,
  validator_duties, eth2_network,
  spec/eth2_apis/callsigs_types,
  eth2_json_rpc_serialization

type
  RpcServer* = RpcHttpServer

logScope: topics = "valapi"

proc toBlockSlot(blckRef: BlockRef): BlockSlot =
  blckRef.atSlot(blckRef.slot)

proc parseRoot(str: string): Eth2Digest =
  return Eth2Digest(data: hexToByteArray[32](str))

proc parsePubkey(str: string): ValidatorPubKey =
  let pubkeyRes = fromHex(ValidatorPubKey, str)
  if pubkeyRes.isErr:
    raise newException(CatchableError, "Not a valid public key")
  return pubkeyRes[]

proc doChecksAndGetCurrentHead(node: BeaconNode, slot: Slot): BlockRef =
  result = node.blockPool.head.blck
  if not node.isSynced(result):
    raise newException(CatchableError, "Cannot fulfill request until ndoe is synced")
  # TODO for now we limit the requests arbitrarily by up to 2 epochs into the future
  if result.slot + uint64(2 * SLOTS_PER_EPOCH) < slot:
    raise newException(CatchableError, "Requesting way ahead of the current head")

proc doChecksAndGetCurrentHead(node: BeaconNode, epoch: Epoch): BlockRef =
  node.doChecksAndGetCurrentHead(epoch.compute_start_slot_at_epoch)

# TODO currently this function throws if the validator isn't found - is this OK?
proc getValidatorInfoFromValidatorId(
    state: BeaconState,
    current_epoch: Epoch,
    validatorId: string,
    status = ""):
    Option[BeaconStatesValidatorsTuple] =
  const allowedStatuses = ["", "pending", "pending_initialized", "pending_queued",
    "active", "active_ongoing", "active_exiting", "active_slashed", "exited",
    "exited_unslashed", "exited_slashed", "withdrawal", "withdrawal_possible",
    "withdrawal_done"]
  if status notin allowedStatuses:
    raise newException(CatchableError, "Invalid status requested")

  let validator = if validatorId.startsWith("0x"):
    let pubkey = parsePubkey(validatorId)
    let idx = state.validators.asSeq.findIt(it.pubKey == pubkey)
    if idx == -1:
      raise newException(CatchableError, "Could not find validator")
    state.validators[idx]
  else:
    var valIdx: BiggestUInt
    if parseBiggestUInt(validatorId, valIdx) != validatorId.len:
      raise newException(CatchableError, "Not a valid index")
    if state.validators.len.uint64 >= valIdx:
      raise newException(CatchableError, "Index out of bounds")
    state.validators[valIdx]

  # time to determine the status of the validator - the code mimics
  # whatever is detailed here: https://hackmd.io/ofFJ5gOmQpu1jjHilHbdQQ
  let actual_status = if validator.activation_epoch > current_epoch:
    # pending
    if validator.activation_eligibility_epoch == FAR_FUTURE_EPOCH:
      "pending_initialized"
    else:
      # validator.activation_eligibility_epoch < FAR_FUTURE_EPOCH:
      "pending_queued"
  elif validator.activation_epoch <= current_epoch and
      current_epoch < validator.exit_epoch:
    # active
    if validator.exit_epoch == FAR_FUTURE_EPOCH:
      "active_ongoing"
    elif not validator.slashed:
      # validator.exit_epoch < FAR_FUTURE_EPOCH
      "active_exiting"
    else:
      # validator.exit_epoch < FAR_FUTURE_EPOCH and validator.slashed:
      "active_slashed"
  elif validator.exit_epoch <= current_epoch and
      current_epoch < validator.withdrawable_epoch:
    # exited
    if not validator.slashed:
      "exited_unslashed"
    else:
      # validator.slashed
      "exited_slashed"
  elif validator.withdrawable_epoch <= current_epoch:
    # withdrawal
    if validator.effective_balance != 0:
      "withdrawal_possible"
    else:
      # validator.effective_balance == 0
      "withdrawal_done"
  else:
    raise newException(CatchableError, "Invalid validator status")

  # if the requested status doesn't match the actual status
  if status != "" and status notin actual_status:
    return none(BeaconStatesValidatorsTuple)

  return some((validator: validator, status: actual_status,
                balance: validator.effective_balance))

proc getBlockSlotFromString(node: BeaconNode, slot: string): BlockSlot =
  var parsed: BiggestUInt
  if parseBiggestUInt(slot, parsed) != slot.len:
    raise newException(CatchableError, "Not a valid slot number")
  let head = node.doChecksAndGetCurrentHead(parsed.Slot)
  return head.atSlot(parsed.Slot)

proc getBlockDataFromBlockId(node: BeaconNode, blockId: string): BlockData =
  result = case blockId:
    of "head":
      node.blockPool.get(node.blockPool.head.blck)
    of "genesis":
      node.blockPool.get(node.blockPool.tail)
    of "finalized":
      node.blockPool.get(node.blockPool.finalizedHead.blck)
    else:
      if blockId.startsWith("0x"):
        let blckRoot = parseRoot(blockId)
        let blockData = node.blockPool.get(blckRoot)
        if blockData.isNone:
          raise newException(CatchableError, "Block not found")
        blockData.get()
      else:
        let blockSlot = node.getBlockSlotFromString(blockId)
        if blockSlot.blck.isNil:
          raise newException(CatchableError, "Block not found")
        node.blockPool.get(blockSlot.blck)

proc stateIdToBlockSlot(node: BeaconNode, stateId: string): BlockSlot =
  result = case stateId:
    of "head":
      node.blockPool.head.blck.toBlockSlot()
    of "genesis":
      node.blockPool.tail.toBlockSlot()
    of "finalized":
      node.blockPool.finalizedHead
    of "justified":
      node.blockPool.justifiedState.blck.atSlot(
        node.blockPool.justifiedState.data.data.slot)
    else:
      if stateId.startsWith("0x"):
        let blckRoot = parseRoot(stateId)
        let blckRef = node.blockPool.getRef(blckRoot)
        if blckRef.isNil:
          raise newException(CatchableError, "Block not found")
        blckRef.toBlockSlot()
      else:
        node.getBlockSlotFromString(stateId)

# TODO Probably the `beacon` ones should be defined elsewhere...?

proc installValidatorApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =

  let GENESIS_FORK_VERSION = node.config.runtimePreset.GENESIS_FORK_VERSION

  template withStateForStateId(stateId: string, body: untyped): untyped =
    node.blockPool.withState(node.blockPool.tmpState,
                             node.stateIdToBlockSlot(stateId)):
      body

  rpcServer.rpc("get_v1_beacon_genesis") do () -> BeaconGenesisTuple:
    return (genesis_time: node.blockPool.headState.data.data.genesis_time,
             genesis_validators_root:
              node.blockPool.headState.data.data.genesis_validators_root,
             genesis_fork_version: GENESIS_FORK_VERSION)

  rpcServer.rpc("get_v1_beacon_states_root") do (stateId: string) -> Eth2Digest:
    withStateForStateId(stateId):
      return hashedState.root

  rpcServer.rpc("get_v1_beacon_states_fork") do (stateId: string) -> Fork:
    withStateForStateId(stateId):
      return state.fork

  rpcServer.rpc("get_v1_beacon_states_finality_checkpoints") do (
      stateId: string) -> BeaconStatesFinalityCheckpointsTuple:
    withStateForStateId(stateId):
      return (previous_justified: state.previous_justified_checkpoint,
              current_justified: state.current_justified_checkpoint,
              finalized: state.finalized_checkpoint)

  rpcServer.rpc("get_v1_beacon_states_stateId_validators") do (
      stateId: string, validatorIds: seq[string],
      status: string) -> seq[BeaconStatesValidatorsTuple]:
    let current_epoch = get_current_epoch(node.blockPool.headState.data.data)
    withStateForStateId(stateId):
      for validatorId in validatorIds:
        let res = state.getValidatorInfoFromValidatorId(
          current_epoch, validatorId, status)
        if res.isSome():
          result.add(res.get())

  rpcServer.rpc("get_v1_beacon_states_stateId_validators_validatorId") do (
      stateId: string, validatorId: string) -> BeaconStatesValidatorsTuple:
    let current_epoch = get_current_epoch(node.blockPool.headState.data.data)
    withStateForStateId(stateId):
      let res = state.getValidatorInfoFromValidatorId(current_epoch, validatorId)
      if res.isNone:
        # TODO should we raise here? Maybe this is different from the array case...
        raise newException(CatchableError, "Validator status differs")
      return res.get()

  rpcServer.rpc("get_v1_beacon_states_stateId_committees_epoch") do (
      stateId: string, epoch: uint64, index: uint64, slot: uint64) ->
      seq[BeaconStatesCommitteesTuple]:
    withStateForStateId(stateId):
      var cache = StateCache() # TODO is this OK?

      proc getCommittee(slot: Slot, index: CommitteeIndex): BeaconStatesCommitteesTuple =
        let vals = get_beacon_committee(state, slot, index, cache).mapIt(it.uint64)
        return (index: index.uint64, slot: slot.uint64, validators: vals)

      proc forSlot(slot: Slot, res: var seq[BeaconStatesCommitteesTuple]) =
        if index == 0: # TODO this means if the parameter is missing (its optional)
          let committees_per_slot = get_committee_count_per_slot(state, slot, cache)
          for committee_index in 0'u64..<committees_per_slot:
            res.add(getCommittee(slot, committee_index.CommitteeIndex))
        else:
          res.add(getCommittee(slot, index.CommitteeIndex))

      if slot == 0: # TODO this means if the parameter is missing (its optional)
        for i in 0 ..< SLOTS_PER_EPOCH:
          forSlot(compute_start_slot_at_epoch(epoch.Epoch) + i, result)
      else:
        forSlot(slot.Slot, result)

  rpcServer.rpc("get_v1_beacon_headers") do (
      slot: uint64, parent_root: Eth2Digest) -> seq[BeaconHeadersTuple]:
    # @mratsim: I'm adding a toposorted iterator that returns all blocks from last finalization to all heads in the dual fork choice PR @viktor

    # filterIt(dag.blocks.values(), it.blck.slot == slot_of_interest)
    # maybe usesBlockPool.heads ??? or getBlockRange ???

    # https://discordapp.com/channels/613988663034118151/614014714590134292/726095138484518912

    discard # raise newException(CatchableError, "Not implemented") # cannot compile...

  rpcServer.rpc("get_v1_beacon_headers_blockId") do (
      blockId: string) -> tuple[canonical: bool, header: SignedBeaconBlockHeader]:
    let bd = node.getBlockDataFromBlockId(blockId)
    let tsbb = bd.data
    result.header.signature.blob = tsbb.signature.data

    result.header.message.slot = tsbb.message.slot
    result.header.message.proposer_index = tsbb.message.proposer_index
    result.header.message.parent_root = tsbb.message.parent_root
    result.header.message.state_root = tsbb.message.state_root
    result.header.message.body_root = tsbb.message.body.hash_tree_root()

    result.canonical = bd.refs.isAncestorOf(node.blockPool.head.blck)

  rpcServer.rpc("get_v1_beacon_blocks_blockId") do (
      blockId: string) -> TrustedSignedBeaconBlock:
    return node.getBlockDataFromBlockId(blockId).data

  rpcServer.rpc("get_v1_beacon_blocks_blockId_root") do (
      blockId: string) -> Eth2Digest:
    return node.getBlockDataFromBlockId(blockId).data.message.state_root

  rpcServer.rpc("get_v1_beacon_blocks_blockId_attestations") do (
      blockId: string) -> seq[TrustedAttestation]:
    return node.getBlockDataFromBlockId(blockId).data.message.body.attestations.asSeq

  rpcServer.rpc("post_v1_beacon_pool_attestations") do (
      attestation: Attestation) -> bool:
    node.sendAttestation(attestation)
    return true

  rpcServer.rpc("get_v1_config_fork_schedule") do (
      ) -> seq[tuple[epoch: uint64, version: Version]]:
    discard # raise newException(CatchableError, "Not implemented") # cannot compile...

  rpcServer.rpc("get_v1_debug_beacon_states_stateId") do (
      stateId: string) -> BeaconState:
    withStateForStateId(stateId):
      return state

  rpcServer.rpc("get_v1_validator_block") do (
      slot: Slot, graffiti: GraffitiBytes, randao_reveal: ValidatorSig) -> BeaconBlock:
    debug "get_v1_validator_block", slot = slot
    let head = node.doChecksAndGetCurrentHead(slot)
    let proposer = node.blockPool.getProposer(head, slot)
    if proposer.isNone():
      raise newException(CatchableError, "could not retrieve block for slot: " & $slot)
    let valInfo = ValidatorInfoForMakeBeaconBlock(kind: viRandao_reveal,
                                                  randao_reveal: randao_reveal)
    let res = makeBeaconBlockForHeadAndSlot(
      node, valInfo, proposer.get()[0], graffiti, head, slot)
    if res.message.isNone():
      raise newException(CatchableError, "could not retrieve block for slot: " & $slot)
    return res.message.get()

  rpcServer.rpc("post_v1_validator_block") do (body: SignedBeaconBlock) -> bool:
    debug "post_v1_validator_block",
      slot = body.message.slot,
      prop_idx = body.message.proposer_index
    let head = node.doChecksAndGetCurrentHead(body.message.slot)

    if head.slot >= body.message.slot:
      raise newException(CatchableError,
        "Proposal is for a past slot: " & $body.message.slot)
    if head == await proposeSignedBlock(node, head, AttachedValidator(), body):
      raise newException(CatchableError, "Could not propose block")
    return true

  rpcServer.rpc("get_v1_validator_attestation") do (
      slot: Slot, committee_index: CommitteeIndex) -> AttestationData:
    debug "get_v1_validator_attestation", slot = slot
    let head = node.doChecksAndGetCurrentHead(slot)

    node.blockPool.withState(node.blockPool.tmpState, head.atSlot(slot)):
      return makeAttestationData(state, slot, committee_index.uint64, blck.root)

  rpcServer.rpc("get_v1_validator_aggregate_and_proof") do (
      attestation_data: AttestationData)-> Attestation:
    debug "get_v1_validator_aggregate_and_proof"
    raise newException(CatchableError, "Not implemented")

  rpcServer.rpc("post_v1_validator_aggregate_and_proof") do (
      payload: SignedAggregateAndProof) -> bool:
    debug "post_v1_validator_aggregate_and_proof"
    raise newException(CatchableError, "Not implemented")

  rpcServer.rpc("post_v1_validator_duties_attester") do (
      epoch: Epoch, public_keys: seq[ValidatorPubKey]) -> seq[AttesterDuties]:
    debug "post_v1_validator_duties_attester", epoch = epoch
    let head = node.doChecksAndGetCurrentHead(epoch)

    let attestationHead = head.atSlot(compute_start_slot_at_epoch(epoch))
    node.blockPool.withState(node.blockPool.tmpState, attestationHead):
      for pubkey in public_keys:
        let idx = state.validators.asSeq.findIt(it.pubKey == pubkey)
        if idx == -1:
          continue
        let ca = state.get_committee_assignment(epoch, idx.ValidatorIndex)
        if ca.isSome:
          result.add((public_key: pubkey,
                      committee_index: ca.get.b,
                      committee_length: ca.get.a.len.uint64,
                      validator_committee_index: ca.get.a.find(idx.ValidatorIndex).uint64,
                      slot: ca.get.c))

  rpcServer.rpc("get_v1_validator_duties_proposer") do (
      epoch: Epoch) -> seq[ValidatorPubkeySlotPair]:
    debug "get_v1_validator_duties_proposer", epoch = epoch
    let head = node.doChecksAndGetCurrentHead(epoch)

    for i in 0 ..< SLOTS_PER_EPOCH:
      let currSlot = compute_start_slot_at_epoch(epoch) + i
      let proposer = node.blockPool.getProposer(head, currSlot)
      if proposer.isSome():
        result.add((public_key: proposer.get()[1], slot: currSlot))

  rpcServer.rpc("post_v1_validator_beacon_committee_subscriptions") do (
      committee_index: CommitteeIndex, slot: Slot, aggregator: bool,
      validator_pubkey: ValidatorPubKey, slot_signature: ValidatorSig) -> bool:
    debug "post_v1_validator_beacon_committee_subscriptions"
    raise newException(CatchableError, "Not implemented")
