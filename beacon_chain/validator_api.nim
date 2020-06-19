# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  tables, strutils, parseutils,

  # Nimble packages
  stew/[objects],
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

# TODO Probably the `beacon` ones should be defined elsewhere...?

proc installValidatorApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =

  template withStateForSlot(stateId: string, body: untyped): untyped =
    var res: BiggestInt
    if parseBiggestInt(stateId, res) == stateId.len:
      raise newException(CatchableError, "Not a valid slot number")
    let head = node.updateHead()
    let blockSlot = head.atSlot(res.Slot)
    node.blockPool.withState(node.blockPool.tmpState, blockSlot):
      body

  rpcServer.rpc("get_v1_beacon_genesis") do () -> BeaconGenesisTuple:
    debug "get_v1_beacon_genesis"
    return (genesis_time: node.blockPool.headState.data.data.genesis_time,
             genesis_validators_root:
              node.blockPool.headState.data.data.genesis_validators_root,
             genesis_fork_version: Version(GENESIS_FORK_VERSION))

  rpcServer.rpc("get_v1_beacon_states_root") do (stateId: string) -> Eth2Digest:
    debug "get_v1_beacon_states_root", stateId = stateId
    # TODO do we need to call node.updateHead() before using headState?
    result = case stateId:
      of "head":
        node.blockPool.headState.blck.root
      of "genesis":
        node.blockPool.headState.data.data.genesis_validators_root
      of "finalized":
        node.blockPool.headState.data.data.finalized_checkpoint.root
      of "justified":
        node.blockPool.headState.data.data.current_justified_checkpoint.root
      else:
        if stateId.startsWith("0x"):
          # TODO not sure if `fromHex` is the right thing here...
          # https://github.com/ethereum/eth2.0-APIs/issues/37#issuecomment-638566144
          # we return whatever was passed to us (this is a nonsense request)
          fromHex(Eth2Digest, stateId[2..<stateId.len]) # skip first 2 chars
        else:
          withStateForSlot(stateId):
            hashedState.root

  rpcServer.rpc("get_v1_beacon_states_fork") do (stateId: string) -> Fork:
    debug "get_v1_beacon_states_fork", stateId = stateId
    result = case stateId:
      of "head":
        node.blockPool.headState.data.data.fork
      of "genesis":
        Fork(previous_version: Version(GENESIS_FORK_VERSION),
             current_version: Version(GENESIS_FORK_VERSION),
             epoch: GENESIS_EPOCH)
      of "finalized":
        node.blockPool.withState(node.blockPool.tmpState, node.blockPool.finalizedHead):
          state.fork
      of "justified":
        node.blockPool.justifiedState.data.data.fork
      else:
        if stateId.startsWith("0x"):
          # TODO not sure if `fromHex` is the right thing here...
          # https://github.com/ethereum/eth2.0-APIs/issues/37#issuecomment-638566144
          let blckRoot = fromHex(Eth2Digest, stateId[2..<stateId.len]) # skip first 2 chars
          let blckRef = node.blockPool.getRef(blckRoot)
          if blckRef.isNil:
            raise newException(CatchableError, "Block not found")
          let blckSlot = blckRef.atSlot(blckRef.slot)
          node.blockPool.withState(node.blockPool.tmpState, blckSlot):
            state.fork
        else:
          withStateForSlot(stateId):
            state.fork

  rpcServer.rpc("post_v1_beacon_pool_attestations") do (
      attestation: Attestation) -> bool:
    node.sendAttestation(attestation)
    return true

  rpcServer.rpc("get_v1_validator_blocks") do (
      slot: Slot, graffiti: Eth2Digest, randao_reveal: ValidatorSig) -> BeaconBlock:
    debug "get_v1_validator_blocks", slot = slot
    let head = node.updateHead()
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

  rpcServer.rpc("post_v1_beacon_blocks") do (body: SignedBeaconBlock) -> bool:
    debug "post_v1_beacon_blocks",
      slot = body.message.slot,
      prop_idx = body.message.proposer_index

    let head = node.updateHead()
    if head.slot >= body.message.slot:
      warn "Skipping proposal, have newer head already",
        headSlot = shortLog(head.slot),
        headBlockRoot = shortLog(head.root),
        slot = shortLog(body.message.slot),
        cat = "fastforward"
      raise newException(CatchableError,
        "Proposal is for a past slot: " & $body.message.slot)
    if head == await proposeSignedBlock(node, head, AttachedValidator(), 
                                        body, hash_tree_root(body.message)):
      raise newException(CatchableError, "Could not propose block")
    return true

  rpcServer.rpc("get_v1_validator_attestation_data") do (
      slot: Slot, committee_index: CommitteeIndex) -> AttestationData:
    let head = node.updateHead()
    let attestationHead = head.atSlot(slot)
    node.blockPool.withState(node.blockPool.tmpState, attestationHead):
      return makeAttestationData(state, slot, committee_index.uint64, blck.root)

  rpcServer.rpc("get_v1_validator_aggregate_attestation") do (
      attestation_data: AttestationData)-> Attestation:
    debug "get_v1_validator_aggregate_attestation"

  rpcServer.rpc("post_v1_validator_aggregate_and_proof") do (
      payload: SignedAggregateAndProof) -> bool:
    node.network.broadcast(node.topicAggregateAndProofs, payload)
    return true

  rpcServer.rpc("post_v1_validator_duties_attester") do (
      epoch: Epoch, public_keys: seq[ValidatorPubKey]) -> seq[AttesterDuties]:
    debug "post_v1_validator_duties_attester", epoch = epoch
    let head = node.updateHead()
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
    let head = node.updateHead()
    for i in 0 ..< SLOTS_PER_EPOCH:
      let currSlot = (compute_start_slot_at_epoch(epoch).int + i).Slot
      let proposer = node.blockPool.getProposer(head, currSlot)
      if proposer.isSome():
        result.add((public_key: proposer.get()[1], slot: currSlot))

  rpcServer.rpc("post_v1_validator_beacon_committee_subscriptions") do (
      committee_index: CommitteeIndex, slot: Slot, aggregator: bool,
      validator_pubkey: ValidatorPubKey, slot_signature: ValidatorSig) -> bool:
    debug "post_v1_validator_beacon_committee_subscriptions"
    raise newException(CatchableError, "Not implemented")
