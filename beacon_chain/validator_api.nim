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
  stew/[objects, bitseqs],
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

  rpcServer.rpc("get_v1_validator_blocks") do (slot: Slot, graffiti: Eth2Digest, randao_reveal: ValidatorSig) -> BeaconBlock:
    
    var head = node.updateHead()

    let proposer = node.blockPool.getProposer(head, slot)
    # TODO how do we handle the case when we cannot return a meaningful block? 404...
    doAssert(proposer.isSome())

    let valInfo = ValidatorInfoForMakeBeaconBlock(kind: viRandao_reveal, randao_reveal: randao_reveal)
    let res = makeBeaconBlockForHeadAndSlot(node, valInfo, proposer.get()[0], graffiti, head, slot)

    # TODO how do we handle the case when we cannot return a meaningful block? 404...
    doAssert(res.message.isSome())
    return res.message.get()

  rpcServer.rpc("post_v1_beacon_blocks") do (body: SignedBeaconBlock):
    onBeaconBlock(node, body)

  rpcServer.rpc("get_v1_validator_attestation_data") do (slot: Slot, committee_index: CommitteeIndex) -> AttestationData:
    discard

  rpcServer.rpc("get_v1_validator_aggregate_attestation") do (query: Eth2Digest)-> Attestation:
    # TODO look at attestation.data.beacon_block_root
    discard

  rpcServer.rpc("post_v1_validator_aggregate_and_proof") do (payload: SignedAggregateAndProof):
    discard

  rpcServer.rpc("post_v1_validator_duties_attester") do (epoch: Epoch, public_keys: seq[ValidatorPubKey]) -> seq[AttesterDuties]:
    discard

  rpcServer.rpc("get_v1_validator_duties_proposer") do (epoch: Epoch) -> seq[ValidatorPubkeySlotPair]:
    var cache = get_empty_per_epoch_cache()
    return get_beacon_proposer_indexes_for_epoch(node.blockPool.headState.data.data, epoch, cache).mapIt(ValidatorPubkeySlotPair(
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
