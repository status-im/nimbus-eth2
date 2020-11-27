# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[parseutils, sequtils, strutils],

  json_rpc/[rpcserver, jsonmarshal],
  chronicles,
  ../beacon_node_common, ../eth2_json_rpc_serialization, ../eth2_network,
  ../validator_duties,
  ../block_pools/chain_dag, ../exit_pool,
  ../spec/[crypto, digest, datatypes, validator],
  ../spec/eth2_apis/callsigs_types,
  ../ssz/merkleization,
  ./rpc_utils

logScope: topics = "beaconapi"

type
  RpcServer = RpcHttpServer

template unimplemented() =
  raise (ref CatchableError)(msg: "Unimplemented")

proc parsePubkey(str: string): ValidatorPubKey =
  const expectedLen = RawPubKeySize * 2 + 2
  if str.len != expectedLen: # +2 because of the `0x` prefix
    raise newException(ValueError,
      "A hex public key should be exactly " & $expectedLen & " characters. " &
      $str.len & " provided")
  let pubkeyRes = fromHex(ValidatorPubKey, str)
  if pubkeyRes.isErr:
    raise newException(CatchableError, "Not a valid public key")
  return pubkeyRes[]

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

  var validatorIdx: uint64
  let validator = if validatorId.startsWith("0x"):
    let pubkey = parsePubkey(validatorId)
    let idx = state.validators.asSeq.findIt(it.pubKey == pubkey)
    if idx == -1:
      raise newException(CatchableError, "Could not find validator")
    validatorIdx = idx.uint64
    state.validators[idx]
  else:
    if parseBiggestUInt(validatorId, validatorIdx) != validatorId.len:
      raise newException(CatchableError, "Not a valid index")
    if validatorIdx > state.validators.lenu64:
      raise newException(CatchableError, "Index out of bounds")
    state.validators[validatorIdx]

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

  return some((validator: validator,
               index: validatorIdx,
               status: actual_status,
               balance: validator.effective_balance))

proc getBlockDataFromBlockId(node: BeaconNode, blockId: string): BlockData =
  result = case blockId:
    of "head":
      node.chainDag.get(node.chainDag.head)
    of "genesis":
      node.chainDag.getGenesisBlockData()
    of "finalized":
      node.chainDag.get(node.chainDag.finalizedHead.blck)
    else:
      if blockId.startsWith("0x"):
        let blckRoot = parseRoot(blockId)
        let blockData = node.chainDag.get(blckRoot)
        if blockData.isNone:
          raise newException(CatchableError, "Block not found")
        blockData.get()
      else:
        let blockSlot = node.getBlockSlotFromString(blockId)
        if blockSlot.blck.isNil:
          raise newException(CatchableError, "Block not found")
        node.chainDag.get(blockSlot.blck)

proc installBeaconApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  rpcServer.rpc("get_v1_beacon_genesis") do () -> BeaconGenesisTuple:
    return (
      genesis_time: node.chainDag.headState.data.data.genesis_time,
      genesis_validators_root:
        node.chainDag.headState.data.data.genesis_validators_root,
      genesis_fork_version: node.config.runtimePreset.GENESIS_FORK_VERSION
    )

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
    let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
    withStateForStateId(stateId):
      for validatorId in validatorIds:
        let res = state.getValidatorInfoFromValidatorId(
          current_epoch, validatorId, status)
        if res.isSome():
          result.add(res.get())

  rpcServer.rpc("get_v1_beacon_states_stateId_validators_validatorId") do (
      stateId: string, validatorId: string) -> BeaconStatesValidatorsTuple:
    let current_epoch = get_current_epoch(node.chainDag.headState.data.data)
    withStateForStateId(stateId):
      let res = state.getValidatorInfoFromValidatorId(current_epoch, validatorId)
      if res.isNone:
        # TODO should we raise here? Maybe this is different from the array case...
        raise newException(CatchableError, "Validator status differs")
      return res.get()

  rpcServer.rpc("get_v1_beacon_states_stateId_validator_balances") do (
      stateId: string) -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_beacon_states_stateId_committees_epoch") do (
      stateId: string, epoch: uint64, index: uint64, slot: uint64) ->
      seq[BeaconStatesCommitteesTuple]:
    checkEpochToSlotOverflow(epoch.Epoch)
    withStateForStateId(stateId):
      proc getCommittee(slot: Slot, index: CommitteeIndex): BeaconStatesCommitteesTuple =
        let vals = get_beacon_committee(state, slot, index, cache).mapIt(it.uint64)
        return (index: index.uint64, slot: slot.uint64, validators: vals)

      proc forSlot(slot: Slot, res: var seq[BeaconStatesCommitteesTuple]) =
        let committees_per_slot =
          get_committee_count_per_slot(state, slot.epoch, cache)
        if index == 0: # parameter is missing (it's optional)
          for committee_index in 0'u64..<committees_per_slot:
            res.add(getCommittee(slot, committee_index.CommitteeIndex))
        else:
          if index >= committees_per_slot:
            raise newException(ValueError, "Committee index out of bounds")
          res.add(getCommittee(slot, index.CommitteeIndex))

      if slot == 0: # parameter is missing (it's optional)
        for i in 0 ..< SLOTS_PER_EPOCH:
          forSlot(compute_start_slot_at_epoch(epoch.Epoch) + i, result)
      else:
        forSlot(slot.Slot, result)

  rpcServer.rpc("get_v1_beacon_headers") do (
      slot: uint64, parent_root: Eth2Digest) -> seq[BeaconHeadersTuple]:
    unimplemented()

  rpcServer.rpc("get_v1_beacon_headers_blockId") do (
      blockId: string) -> tuple[canonical: bool, header: SignedBeaconBlockHeader]:
    let bd = node.getBlockDataFromBlockId(blockId)
    let tsbb = bd.data
    result.header.signature = ValidatorSig.init tsbb.signature.data

    result.header.message.slot = tsbb.message.slot
    result.header.message.proposer_index = tsbb.message.proposer_index
    result.header.message.parent_root = tsbb.message.parent_root
    result.header.message.state_root = tsbb.message.state_root
    result.header.message.body_root = tsbb.message.body.hash_tree_root()

    result.canonical = bd.refs.isAncestorOf(node.chainDag.head)

  rpcServer.rpc("get_v1_beacon_blocks_blockId") do (
      blockId: string) -> TrustedSignedBeaconBlock:
    return node.getBlockDataFromBlockId(blockId).data

  rpcServer.rpc("get_v1_beacon_blocks_blockId_root") do (
      blockId: string) -> Eth2Digest:
    return node.getBlockDataFromBlockId(blockId).data.message.state_root

  rpcServer.rpc("get_v1_beacon_blocks_blockId_attestations") do (
      blockId: string) -> seq[TrustedAttestation]:
    return node.getBlockDataFromBlockId(blockId).data.message.body.attestations.asSeq

  rpcServer.rpc("get_v1_beacon_pool_attestations") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("post_v1_beacon_pool_attestations") do (
      attestation: Attestation) -> bool:
    node.sendAttestation(attestation)
    return true

  rpcServer.rpc("get_v1_beacon_pool_attester_slahsings") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("post_v1_beacon_pool_attester_slahsings") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_beacon_pool_proposer_slashings") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("post_v1_beacon_pool_proposer_slashings") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("get_v1_beacon_pool_voluntary_exits") do () -> JsonNode:
    unimplemented()

  rpcServer.rpc("post_v1_beacon_pool_voluntary_exits") do (
      exit: SignedVoluntaryExit) -> bool:
    doAssert node.exitPool != nil
    let validity = node.exitPool[].validateVoluntaryExit(exit)
    if validity.isOk:
      node.sendVoluntaryExit(exit)
    else:
      raise newException(ValueError, $(validity.error[1]))
    return true

