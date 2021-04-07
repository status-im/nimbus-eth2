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
  ../beacon_node_common, ../validators/validator_duties,
  ../consensus_object_pools/[block_pools_types, blockchain_dag],
  ../spec/[datatypes, digest, helpers]

export blockchain_dag

template withStateForStateId*(stateId: string, body: untyped): untyped =
  let
    bs = node.stateIdToBlockSlot(stateId)

  template isState(state: StateData): bool =
    state.blck.atSlot(getStateField(state, slot)) == bs

  if isState(node.chainDag.headState):
    withStateVars(node.chainDag.headState):
      var cache {.inject.}: StateCache
      body
  else:
    let rpcState = assignClone(node.chainDag.headState)
    node.chainDag.withState(rpcState[], bs):
      body

proc toBlockSlot*(blckRef: BlockRef): BlockSlot =
  blckRef.atSlot(blckRef.slot)

proc parseRoot*(str: string): Eth2Digest {.raises: [Defect, ValueError].} =
  Eth2Digest(data: hexToByteArray[32](str))

func checkEpochToSlotOverflow*(epoch: Epoch) {.raises: [Defect, ValueError].} =
  const maxEpoch = compute_epoch_at_slot(not 0'u64)
  if epoch >= maxEpoch:
    raise newException(
      ValueError, "Requesting epoch for which slot would overflow")

proc doChecksAndGetCurrentHead*(node: BeaconNode, slot: Slot): BlockRef {.raises: [Defect, CatchableError].} =
  result = node.chainDag.head
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
    node.chainDag.head.toBlockSlot()
  of "genesis":
    node.chainDag.getGenesisBlockSlot()
  of "finalized":
    node.chainDag.finalizedHead
  of "justified":
    node.chainDag.head.atEpochStart(
      getStateField(node.chainDag.headState, current_justified_checkpoint).epoch)
  else:
    if stateId.startsWith("0x"):
      let blckRoot = parseRoot(stateId)
      let blckRef = node.chainDag.getRef(blckRoot)
      if blckRef.isNil:
        raise newException(CatchableError, "Block not found")
      blckRef.toBlockSlot()
    else:
      node.getBlockSlotFromString(stateId)
