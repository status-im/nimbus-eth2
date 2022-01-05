# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[strutils, parseutils],
  stew/byteutils,
  ../beacon_node, ../validators/validator_duties,
  ../consensus_object_pools/[block_pools_types, blockchain_dag],
  ../spec/datatypes/base,
  ../spec/[forks, helpers],
  ../spec/eth2_apis/[rpc_types, eth2_json_rpc_serialization]

export forks, rpc_types, eth2_json_rpc_serialization, blockchain_dag

template raiseNoAltairSupport*() =
  raise (ref ValueError)(msg:
    "The JSON-RPC interface does not support certain Altair operations due to changes in block structure - see https://nimbus.guide/rest-api.html for full altair support")

template withStateForStateId*(stateId: string, body: untyped): untyped =
  let
    bs = node.stateIdToBlockSlot(stateId)

  template isState(state: StateData): bool =
    state.blck.atSlot(getStateField(state.data, slot)) == bs

  if isState(node.dag.headState):
    withStateVars(node.dag.headState):
      var cache {.inject, used.}: StateCache
      body
  else:
    let rpcState = assignClone(node.dag.headState)
    node.dag.withUpdatedState(rpcState[], bs) do:
      body
    do:
      raise (ref CatchableError)(msg: "Trying to access pruned state")

proc parseRoot*(str: string): Eth2Digest {.raises: [Defect, ValueError].} =
  Eth2Digest(data: hexToByteArray[32](str))

func checkEpochToSlotOverflow*(epoch: Epoch) {.raises: [Defect, ValueError].} =
  const maxEpoch = compute_epoch_at_slot(not 0'u64)
  if epoch >= maxEpoch:
    raise newException(
      ValueError, "Requesting epoch for which slot would overflow")

proc doChecksAndGetCurrentHead*(node: BeaconNode, slot: Slot): BlockRef {.raises: [Defect, CatchableError].} =
  result = node.dag.head
  if not node.isSynced(result):
    raise newException(CatchableError, "Cannot fulfill request until node is synced")
  # TODO for now we limit the requests arbitrarily by up to 2 epochs into the future
  if result.slot + uint64(2 * SLOTS_PER_EPOCH) < slot:
    raise newException(CatchableError, "Requesting way ahead of the current head")

proc doChecksAndGetCurrentHead*(node: BeaconNode, epoch: Epoch): BlockRef {.raises: [Defect, CatchableError].} =
  checkEpochToSlotOverflow(epoch)
  node.doChecksAndGetCurrentHead(epoch.compute_start_slot_at_epoch)

proc getBlockSlotFromString*(node: BeaconNode, slot: string): BlockSlot {.raises: [Defect, CatchableError].} =
  if slot.len == 0:
    raise newException(ValueError, "Empty slot number not allowed")
  var parsed: BiggestUInt
  if parseBiggestUInt(slot, parsed) != slot.len:
    raise newException(ValueError, "Not a valid slot number")
  let head = node.doChecksAndGetCurrentHead(parsed.Slot)
  head.atSlot(parsed.Slot)

proc stateIdToBlockSlot*(node: BeaconNode, stateId: string): BlockSlot {.raises: [Defect, CatchableError].} =
  case stateId:
  of "head":
    node.dag.head.atSlot()
  of "genesis":
    node.dag.genesis.atSlot()
  of "finalized":
    node.dag.finalizedHead
  of "justified":
    node.dag.head.atEpochStart(
      getStateField(node.dag.headState.data, current_justified_checkpoint).epoch)
  else:
    if stateId.startsWith("0x"):
      let stateRoot = parseRoot(stateId)
      if stateRoot == getStateRoot(node.dag.headState.data):
        node.dag.headState.blck.atSlot()
      else:
        # We don't have a state root -> BlockSlot mapping
        raise (ref ValueError)(msg: "State not found")

    else: # Parse as slot number
      node.getBlockSlotFromString(stateId)
