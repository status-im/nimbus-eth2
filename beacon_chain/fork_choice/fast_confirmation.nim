# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/[assign2, bitops2],
  ../consensus_object_pools/spec_cache,
  "."/fork_choice_types

from ../consensus_object_pools/blockchain_dag import
  fork_choice_balances, getShufflingRef, ForkChoiceInfoOffset

export fork_choice_types

const
  AttesterDutyOffsets = [
    ForkChoiceInfoOffset + 1,
    ForkChoiceInfoOffset + 1 + SLOTS_PER_EPOCH.bitWidth]
  AttesterDutyMask = (distinctBase(1.Gwei) shl SLOTS_PER_EPOCH.bitWidth) - 1
  AttesterDutyMasks = [
    AttesterDutyMask shl AttesterDutyOffsets[0],
    AttesterDutyMask shl AttesterDutyOffsets[1]]
  AllAttesterDutiesMask =
    AttesterDutyMasks[0] or AttesterDutyMasks[1]
  ClearAttesterDutyMasks = [
    not AttesterDutyMasks[0],
    not AttesterDutyMasks[1]]
  ClearAllAttesterDutiesMask =
    ClearAttesterDutyMasks[0] or ClearAttesterDutyMasks[1]

func validators*(epochRef: EpochRef): ValidatorInfo =
  ValidatorInfo(
    balances: epochRef.fork_choice_balances,
    shuffling_epochs: [FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH])

func shuffling_index(epoch: Epoch): int =
  (distinctBase(epoch) and distinctBase(1.Epoch)).int

func has_shuffling(
    validators: ValidatorInfo,
    epoch: Epoch, attester_dependent_root: Eth2Digest): bool =
  let i = epoch.shuffling_index
  validators.shuffling_epochs[i] == epoch and
  validators.shuffling_roots[i] == attester_dependent_root

func record_shuffling(
    validators: var ValidatorInfo, shufflingRef: ShufflingRef) =
  let
    i = shufflingRef.epoch.shuffling_index
    offset = AttesterDutyOffsets[i]
    clear_mask = ClearAttesterDutyMasks[i]
  for slot in shufflingRef.epoch.slots:
    let duty_mask = slot.since_epoch_start shl offset
    for committee_index in get_committee_indices(shufflingRef):
      for _, val in shufflingRef.get_beacon_committee(slot, committee_index):
        validators.balances.extend(val.int + 1)
        validators.balances[val] = ForkChoiceBalance(
          (distinctBase(validators.balances[val]) and clear_mask) or duty_mask)
  validators.shuffling_epochs[i] = shufflingRef.epoch
  assign(validators.shuffling_roots[i], shufflingRef.attester_dependent_root)

proc do_update_latest_shufflings(
    validators: var ValidatorInfo,
    dag: ChainDAGRef, current_slot: Slot): Opt[void] =
  var
    epoch = current_slot.epoch
    blck = dag.head.atSlot(epoch.attester_dependent_slot).blck
  if blck == nil:
    return err()
  if not validators.has_shuffling(epoch, blck.bid.root):
    validators.record_shuffling(
      ? dag.getShufflingRef(blck, epoch, preFinalized = false))
  if epoch > GENESIS_EPOCH:
    dec epoch
    blck = blck.atSlot(epoch.attester_dependent_slot).blck
    if blck == nil:
      return err()
    if not validators.has_shuffling(epoch, blck.bid.root):
      validators.record_shuffling(
        ? dag.getShufflingRef(blck, epoch, preFinalized = false))
  ok()

proc update_latest_shufflings*(
    validators: var ValidatorInfo, dag: ChainDAGRef, current_slot: Slot) =
  validators.do_update_latest_shufflings(dag, current_slot).isOkOr:
    assign(validators.shuffling_epochs, [FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH])

func assign_shufflings*(dst: var ValidatorInfo, src: ValidatorInfo) =
  if dst.balances.len > src.balances.len:
    return
  dst.balances.extend(src.balances.len)
  for val, balance in dst.balances.mpairs:
    balance = ForkChoiceBalance(
      (distinctBase(balance) and ClearAllAttesterDutiesMask) or
      (distinctBase(src.balances[val]) and AllAttesterDutiesMask))
  assign(dst.shuffling_epochs, src.shuffling_epochs)
  assign(dst.shuffling_roots, src.shuffling_roots)

func assigned_slot_since_epoch_start(
    balance: ForkChoiceBalance, i: int): uint64 =
  (distinctBase(balance) shr AttesterDutyOffsets[i]) and AttesterDutyMask

iterator assigned_slots*(
    validators: var ValidatorInfo, val_index: ValidatorIndex): Slot =
  if val_index < validators.balances.len.ValidatorIndex:
    for i in 0 .. 1:
      if validators.shuffling_epochs[i] != FAR_FUTURE_EPOCH:
        yield validators.shuffling_epochs[i].start_slot +
          validators.balances[val_index].assigned_slot_since_epoch_start(i)
