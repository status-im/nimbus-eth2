# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  tables, strutils, sequtils,

  # Nimble packages
  stew/[objects],
  chronos, metrics, json_rpc/[rpcserver, jsonmarshal],

  # Local modules
  spec/[datatypes, digest, crypto, validator],
  block_pool,
  beacon_node_common,
  validator_duties,
  spec/eth2_apis/validator_callsigs_types,
  eth2_json_rpc_serialization

type
  RpcServer* = RpcHttpServer

proc installValidatorApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =

  # TODO Probably the `beacon` ones (and not `validator`) should be defined elsewhere...
  rpcServer.rpc("get_v1_beacon_states_fork") do (stateId: string) -> Fork:
    notice "== get_v1_beacon_states_fork", stateId = stateId
    result = case stateId:
      of "head":
        discard node.updateHead() # TODO do we need this?
        node.blockPool.headState.data.data.fork
      of "genesis":
        Fork(previous_version: Version(GENESIS_FORK_VERSION),
             current_version: Version(GENESIS_FORK_VERSION),
             epoch: 0.Epoch)
      of "finalized":
        # TODO
        Fork()
      of "justified":
        # TODO
        Fork()
      else:
        # TODO parse `stateId` as either a number (slot) or a hash (stateRoot)
        Fork()

  # TODO Probably the `beacon` ones (and not `validator`) should be defined elsewhere...
  rpcServer.rpc("get_v1_beacon_genesis") do () -> BeaconGenesisTuple:
    notice "== get_v1_beacon_genesis"
    return BeaconGenesisTuple(genesis_time: node.blockPool.headState.data.data.genesis_time,
                              genesis_validators_root: node.blockPool.headState.data.data.genesis_validators_root,
                              genesis_fork_version: Version(GENESIS_FORK_VERSION))

  rpcServer.rpc("get_v1_validator_blocks") do (slot: Slot, graffiti: Eth2Digest, randao_reveal: ValidatorSig) -> BeaconBlock:
    notice "== get_v1_validator_blocks", slot = slot
    var head = node.updateHead()

    let proposer = node.blockPool.getProposer(head, slot)
    # TODO how do we handle the case when we cannot return a meaningful block? 404...
    doAssert(proposer.isSome())

    let valInfo = ValidatorInfoForMakeBeaconBlock(kind: viRandao_reveal, randao_reveal: randao_reveal)
    let res = makeBeaconBlockForHeadAndSlot(node, valInfo, proposer.get()[0], graffiti, head, slot)

    # TODO how do we handle the case when we cannot return a meaningful block? 404...
    # currently this fails often - perhaps because the block has already been
    # processed and signed with the inProcess validator...
    # doAssert(res.message.isSome())
    return res.message.get(BeaconBlock()) # returning a default if empty

  rpcServer.rpc("post_v1_beacon_blocks") do (body: SignedBeaconBlock) -> bool :
    notice "== post_v1_beacon_blocks"
    # TODO make onBeaconBlock return a result and discard it wherever its unnecessary
    onBeaconBlock(node, body)
    return true

  rpcServer.rpc("get_v1_validator_attestation_data") do (slot: Slot, committee_index: CommitteeIndex) -> AttestationData:
    discard

  rpcServer.rpc("get_v1_validator_aggregate_attestation") do (query: Eth2Digest)-> Attestation:
    # TODO look at attestation.data.beacon_block_root
    discard

  rpcServer.rpc("post_v1_validator_aggregate_and_proof") do (payload: SignedAggregateAndProof):
    discard

  rpcServer.rpc("post_v1_validator_duties_attester") do (epoch: Epoch, public_keys: seq[ValidatorPubKey]) -> seq[AttesterDuties]:
    notice "== post_v1_validator_duties_attester", epoch = epoch
    for pubkey in public_keys:
      let idx = node.blockPool.headState.data.data.validators.asSeq.findIt(it.pubKey == pubkey)
      if idx != -1:
        let res = node.blockPool.headState.data.data.get_committee_assignment(epoch, idx.ValidatorIndex)
        if res.isSome:
          result.add(AttesterDuties(public_key: pubkey,
                                    committee_index: res.get.b,
                                    committee_length: res.get.a.len.uint64,
                                    validator_committee_index: res.get.a.find(idx.ValidatorIndex).uint64,
                                    slot: res.get.c))

  rpcServer.rpc("get_v1_validator_duties_proposer") do (epoch: Epoch) -> seq[ValidatorPubkeySlotPair]:
    notice "== get_v1_validator_duties_proposer", epoch = epoch
    var cache = get_empty_per_epoch_cache()
    result = get_beacon_proposer_indexes_for_epoch(node.blockPool.headState.data.data, epoch, cache).mapIt(ValidatorPubkeySlotPair(
        public_key: node.blockPool.headState.data.data.validators[it.i].pubkey,
        slot: it.s
      ))

  rpcServer.rpc("post_v1_validator_beacon_committee_subscription") do (
      committee_index: CommitteeIndex,
      slot: Slot,
      aggregator: bool,
      validator_pubkey: ValidatorPubKey,
      slot_signature: ValidatorSig):
    discard
