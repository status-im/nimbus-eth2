# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/sets, stew/bitops2,
  ../consensus_object_pools/spec_cache,
  "."/fork_choice_types

from ../consensus_object_pools/blockchain_dag import
  ForkChoiceInfoOffset, fork_choice_balances,
  effective_balance, unslashed_balance,
  getBlockIdAtSlot, getShufflingRef

export fork_choice_types

const
  AttesterDutyOffsets* = [
    ForkChoiceInfoOffset + 1,
    ForkChoiceInfoOffset + 1 + SLOTS_PER_EPOCH.bitWidth,
    ForkChoiceInfoOffset + 1 + SLOTS_PER_EPOCH.bitWidth * 2]
  NumAttesterDuties* = AttesterDutyOffsets.len
  AttesterDutyMask = (distinctBase(1.Gwei) shl SLOTS_PER_EPOCH.bitWidth) - 1
  AttesterDutyMasks = [
    AttesterDutyMask shl AttesterDutyOffsets[0],
    AttesterDutyMask shl AttesterDutyOffsets[1],
    AttesterDutyMask shl AttesterDutyOffsets[2]]
  AllAttesterDutiesMask =
    AttesterDutyMasks[0] or
    AttesterDutyMasks[1] or
    AttesterDutyMasks[2]
  ClearAttesterDutyMasks = [
    not AttesterDutyMasks[0],
    not AttesterDutyMasks[1],
    not AttesterDutyMasks[2]]
  ClearAllAttesterDutiesMask =
    ClearAttesterDutyMasks[0] and
    ClearAttesterDutyMasks[1] and
    ClearAttesterDutyMasks[2]
  DefaultShufflingEpochs* = [
    FAR_FUTURE_EPOCH,
    FAR_FUTURE_EPOCH,
    FAR_FUTURE_EPOCH]

func balance_source*(checkpoint: BalanceCheckpoint): BalanceSource =
  BalanceSource(info: checkpoint, shuffling_epochs: DefaultShufflingEpochs)

func shuffling_index*(epoch: Epoch): int =
  (epoch mod NumAttesterDuties.uint64).int

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

proc do_update_shufflings(
    balance_source: var BalanceSource, dag: ChainDAGRef,
    blck: BlockRef, current_slot: Slot): Opt[void] =
  var
    blck = blck
    epoch = current_slot.epoch
  for i in 0 ..< NumAttesterDuties:
    let dependent_slot = epoch.attester_dependent_slot
    blck = blck.atSlot(dependent_slot).blck
    let dependent_root =
      if blck != nil:
        blck.bid.root
      else:
        (? dag.getBlockIdAtSlot(dependent_slot)).bid.root
    if balance_source.has_shuffling(epoch, dependent_root):
      return ok()
    balance_source.record_shuffling(
      ? dag.getShufflingRef(blck, epoch, preFinalized = true))
    if epoch <= GENESIS_EPOCH:
      return ok()
    dec epoch
  ok()

proc update_latest_shufflings(
    balance_source: var BalanceSource, dag: ChainDAGRef,
    blck: BlockRef, current_slot: Slot): Opt[void] =
  result = balance_source.do_update_shufflings(dag, dag.head, current_slot)
  if result.isErr:
    balance_source.shuffling_epochs = DefaultShufflingEpochs

proc update_latest_shufflings*(
    balance_source: var BalanceSource, dag: ChainDAGRef,
    current_slot: Slot): Opt[void] =
  balance_source.update_latest_shufflings(dag, dag.head, current_slot)

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
    balance_source: BalanceSource, val_index: ValidatorIndex, o = 0): Slot =
  if val_index < balance_source.balances.len.ValidatorIndex:
    var i = o
    while true:
      if balance_source.shuffling_epochs[i] != FAR_FUTURE_EPOCH:
        yield balance_source.shuffling_epochs[i].start_slot +
          balance_source.balances[val_index].assigned_slot_into_epoch(i)
      if i == 0:
        i = NumAttesterDuties
      dec i
      if i == o:
        break

type SlotInfo* = object
  blck*: BlockRef
  support*: Gwei
  adversarial*: Gwei
  total_support*: Gwei
  total_adversarial*: Gwei

func get_ancestor_info*(
    blck: BlockRef, terminal_bid: BlockId, current_slot: Slot): seq[SlotInfo] =
  ## Return a list of ancestors of ``blck`` inclusive back through the last
  ## slot of ``current_slot.epoch - 2``, or ``terminal_bid``, whichever is
  ## encountered first, iff ``terminal_bid`` is an ancestor of ``blck``.
  ## Otherwise, return an empty list.
  ## For slots within the previous and current epoch, an entry is emitted
  ## per slot, even when there are slots without a block. A single extra entry
  ## is emitted for the last block, if it was proposed during an earlier epoch.
  let
    prev_epoch_start = (max(current_slot.epoch, 1.Epoch) - 1).start_slot
    low_slot = max(terminal_bid.slot, max(prev_epoch_start, 1.Slot) - 1)
  result = newSeqOfCap[SlotInfo](current_slot  - low_slot + 1)

  var bs = blck.atSlot(current_slot)
  while bs.blck != nil and bs.slot > low_slot:
    result.add SlotInfo(blck: bs.blck)
    bs = bs.parent
  while bs.blck != nil and not bs.isProposed and bs.slot >= prev_epoch_start:
    result.add SlotInfo(blck: bs.blck)
    bs = bs.parent
  if bs.blck != nil:
    result.add SlotInfo(blck: bs.blck)

  while bs.blck != nil and bs.slot > terminal_bid.slot:
    bs = bs.parent
  if bs.blck == nil or bs.blck.root != terminal_bid.root:
    result.reset()

func get_ancestor_support_by_slot*(
    self: ForkChoiceBackend, balance_source: BalanceSource,
    blck: BlockRef, terminal_bid: BlockId, current_slot: Slot): seq[SlotInfo] =
  ## Return support of the ancestors of ``blck`` grouped by originating slot.
  result = blck.get_ancestor_info(terminal_bid, current_slot)
  if result.len == 0:
    return result

  let
    prev_epoch_start = (max(current_slot.epoch, 1.Epoch) - 1).start_slot
    last_slot = result[^1].blck.slot
    low_slot =
      if last_slot >= prev_epoch_start:
        last_slot
      else:
        last_slot + 1
  for val_index in 0 ..< min(self.votes.len, balance_source.balances.len):
    template balance: ForkChoiceBalance = balance_source.balances[val_index]
    template vote: VoteTracker = self.votes[val_index]
    if vote.slot in low_slot .. current_slot:
      # Collect support of the block per slot:
      # - get_block_support_between_slots
      # - get_current_target_score
      let i = min(current_slot - vote.slot, result.high.uint64).int
      if vote.current_root == result[i].blck.root:
        result[i].support += balance.unslashed_balance
    elif vote.slot == FAR_FUTURE_SLOT:
      # Collect total weight of equivocating participants:
      # - get_adversarial_weight (to current_slot)
      # - compute_empty_slot_support_discount (per slot, between blocks)
      var old_i = -1
      let
        eb = balance.effective_balance
        o = current_slot.epoch.shuffling_index
      for slot in balance_source.assigned_slots(val_index.ValidatorIndex, o):
        if slot in low_slot ..< current_slot:
          let i = min(current_slot - slot, result.high.uint64).int
          if old_i == -1 or result[i].blck != result[old_i].blck:
            result[i].adversarial += eb
            if old_i == -1:
              result[i].total_adversarial += eb
          old_i = i
    else:
      discard

  result[0].total_support = result[0].support
  for i in 1 ..< result.len:
    result[i].total_support = result[i].support + result[i - 1].total_support
    result[i].total_adversarial += result[i - 1].total_adversarial

func get_current_target_score*(
    self: ForkChoiceBackend, head_state: ForkyBeaconState,
    target: BlockRef, heads: seq[BlockRef]): Gwei =
  ## Return the estimate of FFG support of the current epoch target
  ## by using LMD-GHOST votes.
  var roots: HashSet[Eth2Digest]
  roots.incl target.root
  for head in heads:
    var blck = head
    while blck != nil and blck.slot > target.slot:
      blck = blck.parent
    if blck == target:
      blck = head
      while blck != target and not roots.containsOrIncl(blck.root):
        blck = blck.parent

  let current_epoch = head_state.slot.epoch
  doAssert target.slot <= current_epoch.start_slot
  for val_index in 0 ..< min(self.votes.len, head_state.validators.len):
    template validator: Validator = head_state.validators[val_index]
    template vote: VoteTracker = self.votes[val_index]
    if vote.slot.epoch == current_epoch and
        validator.is_active_validator(current_epoch) and
        not validator.slashed and vote.current_root in roots:
      result += validator.effective_balance

proc should_revert_confirmed_on_new_epoch*(
    self: var ForkChoiceBackend, dag: ChainDAGRef, current_slot: Slot): bool =
  # Revert to finalized block if either of the following is true:
  # 1) the latest confirmed block's epoch is older than the previous epoch,
  # 2) [...],
  # 3) the confirmed chain starting from the current epoch observed justified
  #    checkpoint cannot be re-confirmed at the start of the current epoch.
  if self.confirmed.slot.epoch + 1 < current_slot.epoch:
    return true

  template balance_source: BalanceSource = self.current_epoch_observed_justified
  balance_source.update_latest_shufflings(dag, current_slot).isOkOr:
    return true

  false  # TODO: not self.is_confirmed_chain_safe

func should_revert_confirmed_on_new_head*(
    self: var ForkChoiceBackend, blck: BlockRef, current_slot: Slot): bool =
  # Revert to finalized block if either of the following is true:
  # 1) [...],
  # 2) the latest confirmed block doesn't belong to the canonical chain,
  # 3) [...].
  if self.confirmed.slot.epoch + 1 < current_slot.epoch:
    return true

  var blck = blck
  while blck != nil and blck.slot > self.confirmed.slot:
    blck = blck.parent
  blck == nil or blck.root != self.confirmed.root
