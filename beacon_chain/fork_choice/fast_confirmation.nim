# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  stew/bitops2,
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

func balance_source*(checkpoint: BalanceCheckpoint): BalanceSource =
  BalanceSource(
    info: checkpoint,
    shuffling_epochs: [FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH])

func shuffling_index(epoch: Epoch): int =
  (distinctBase(epoch) and distinctBase(1.Epoch)).int

func has_shuffling(
    balance_source: BalanceSource,
    epoch: Epoch, attester_dependent_root: Eth2Digest): bool =
  let i = epoch.shuffling_index
  balance_source.shuffling_epochs[i] == epoch and
  balance_source.shuffling_roots[i] == attester_dependent_root

func record_shuffling(
    balance_source: var BalanceSource, shufflingRef: ShufflingRef) =
  let
    i = shufflingRef.epoch.shuffling_index
    offset = AttesterDutyOffsets[i]
    clear_mask = ClearAttesterDutyMasks[i]
  for slot in shufflingRef.epoch.slots:
    let duty_mask = slot.since_epoch_start shl offset
    for committee_index in get_committee_indices(shufflingRef):
      for _, val in shufflingRef.get_beacon_committee(slot, committee_index):
        balance_source.balances.extend(val.int + 1)
        template balance: ForkChoiceBalance = balance_source.balances[val]
        balance_source.balances[val] = ForkChoiceBalance(
          (distinctBase(balance) and clear_mask) or duty_mask)
  balance_source.shuffling_epochs[i] = shufflingRef.epoch
  balance_source.shuffling_roots[i] = shufflingRef.attester_dependent_root

proc do_update_latest_shufflings(
    balance_source: var BalanceSource,
    dag: ChainDAGRef, current_slot: Slot): Opt[void] =
  var
    epoch = current_slot.epoch
    blck = dag.head.atSlot(epoch.attester_dependent_slot).blck
  if blck == nil:
    return err()
  if not balance_source.has_shuffling(epoch, blck.bid.root):
    balance_source.record_shuffling(
      ? dag.getShufflingRef(blck, epoch, preFinalized = false))
  if epoch > GENESIS_EPOCH:
    dec epoch
    blck = blck.atSlot(epoch.attester_dependent_slot).blck
    if blck == nil:
      return err()
    if not balance_source.has_shuffling(epoch, blck.bid.root):
      balance_source.record_shuffling(
        ? dag.getShufflingRef(blck, epoch, preFinalized = false))
  ok()

proc update_latest_shufflings*(
    balance_source: var BalanceSource, dag: ChainDAGRef, current_slot: Slot) =
  balance_source.do_update_latest_shufflings(dag, current_slot).isOkOr:
    balance_source.shuffling_epochs = [FAR_FUTURE_EPOCH, FAR_FUTURE_EPOCH]

func assign_shufflings*(dst: var BalanceSource, src: BalanceSource) =
  if dst.balances.len > src.balances.len:
    return
  dst.balances.extend(src.balances.len)
  for val, balance in dst.balances.mpairs:
    balance = ForkChoiceBalance(
      (distinctBase(balance) and ClearAllAttesterDutiesMask) or
      (distinctBase(src.balances[val]) and AllAttesterDutiesMask))
  dst.shuffling_epochs = src.shuffling_epochs
  dst.shuffling_roots = src.shuffling_roots

func assigned_slot_into_epoch(
    balance: ForkChoiceBalance, i: int): uint64 =
  (distinctBase(balance) shr AttesterDutyOffsets[i]) and AttesterDutyMask

iterator assigned_slots*(
    balance_source: var BalanceSource, val_index: ValidatorIndex): Slot =
  if val_index < balance_source.balances.len.ValidatorIndex:
    for i in 0 .. 1:
      if balance_source.shuffling_epochs[i] != FAR_FUTURE_EPOCH:
        yield balance_source.shuffling_epochs[i].start_slot +
          balance_source.balances[val_index].assigned_slot_into_epoch(i)
