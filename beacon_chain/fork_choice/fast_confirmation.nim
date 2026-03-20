# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sets, tables], stew/bitops2,
  ../consensus_object_pools/spec_cache,
  "."/[fork_choice_types, proto_array]

from ../consensus_object_pools/blockchain_dag import
  ForkChoiceInfoOffset, fork_choice_balances,
  slashed, effective_balance, unslashed_balance,
  getBlockIdAtSlot, getBlockRef, getEpochRef, getShufflingRef

from ../spec/beaconstate import latest_block_root

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
  for balance in balance_source.balances.mitems:
    balance = ForkChoiceBalance(distinctBase(balance) and clear_mask)
  for slot in shufflingRef.epoch.slots:
    let duty_mask = (slot.since_epoch_start + 1) shl offset
    for committee_index in get_committee_indices(shufflingRef):
      for _, val in shufflingRef.get_beacon_committee(slot, committee_index):
        balance_source.balances.extend(val.int + 1)
        template balance: ForkChoiceBalance = balance_source.balances[val]
        balance = ForkChoiceBalance(distinctBase(balance) or duty_mask)
  balance_source.shuffling_epochs[i] = shufflingRef.epoch
  balance_source.shuffling_roots[i] = shufflingRef.attester_dependent_root

proc do_update_shufflings(
    balance_source: var BalanceSource, dag: ChainDAGRef,
    blck: BlockRef, current_slot: Slot): Opt[void] =
  var
    blck = blck
    epoch = current_slot.epoch
  for i in 0 ..< NumAttesterDuties:
    let
      dependent_slot = epoch.attester_dependent_slot
      dependent_blck = blck.atSlot(dependent_slot).blck
      dependent_root =
        if dependent_blck != nil:
          blck = dependent_blck
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
  let
    clear_mask = ClearAllAttesterDutiesMask
    duty_mask = AllAttesterDutiesMask
  if dst.balances.len > src.balances.len:
    for val in src.balances.len ..< dst.balances.len:
      template balance: ForkChoiceBalance = dst.balances[val]
      balance = ForkChoiceBalance(distinctBase(balance) and clear_mask)
  else:
    dst.balances.extend(src.balances.len)
  for val in 0 ..< src.balances.len:
    template balance: ForkChoiceBalance = dst.balances[val]
    balance = ForkChoiceBalance(
      (distinctBase(balance) and clear_mask) or
      (distinctBase(src.balances[val]) and duty_mask))
  dst.shuffling_epochs = src.shuffling_epochs
  dst.shuffling_roots = src.shuffling_roots

func attester_duty(
    balance: ForkChoiceBalance, i: int): uint64 =
  # 0: Validator was not assigned duties in this epoch (inactive)
  # 1-SLOTS_PER_EPOCH: (1 + since_epoch_start) of attester duty assignment
  (distinctBase(balance) shr AttesterDutyOffsets[i]) and AttesterDutyMask

iterator assigned_slots*(
    balance_source: BalanceSource, val_index: ValidatorIndex, o = 0): Slot =
  if val_index < balance_source.balances.len.ValidatorIndex:
    var i = o
    while true:
      if balance_source.shuffling_epochs[i] != FAR_FUTURE_EPOCH:
        let duty = balance_source.balances[val_index].attester_duty(i)
        if duty != 0:
          yield balance_source.shuffling_epochs[i].start_slot + duty - 1
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
  result = newSeqOfCap[SlotInfo](current_slot - low_slot + 1)

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

func index(chain: seq[SlotInfo], slot, current_slot: Slot): int =
  min(current_slot - slot, chain.high.uint64).int

func low_slot(chain: seq[SlotInfo], current_slot: Slot): Slot =
  let
    prev_epoch_start = (max(current_slot.epoch, 1.Epoch) - 1).start_slot
    last_slot = chain[^1].blck.slot
  if last_slot >= prev_epoch_start:
    last_slot
  else:
    last_slot + 1

func noncanonical_ancestors(
    chain: seq[SlotInfo], heads: seq[BlockRef],
    low_slot, current_slot: Slot): Table[Eth2Digest, int] =
  if chain.len == 0:
    return result

  for i in 0 ..< chain.high:
    result[chain[i].blck.root] = i

  for head in heads:
    var blck = head
    while blck != nil and blck.slot in low_slot .. current_slot:
      let
        i = chain.index(blck.slot, current_slot)
        ancestor =
          if blck == chain[i].blck:
            i
          else:
            result.getOrDefault(blck.root, -1)
      if ancestor != -1:
        var b = head
        while b != blck:
          result[b.root] = ancestor
          b = b.parent
        break
      blck = blck.parent

func get_ancestor_support_by_slot*(
    self: ForkChoiceBackend, balance_source: BalanceSource,
    heads: seq[BlockRef], blck: BlockRef, terminal_bid: BlockId,
    current_slot: Slot): seq[SlotInfo] =
  ## Return support of the ancestors of ``blck`` grouped by originating slot.
  result = blck.get_ancestor_info(terminal_bid, current_slot)
  if result.len == 0:
    return result

  let
    low_slot = result.low_slot(current_slot)
    noncanonical = result.noncanonical_ancestors(heads, low_slot, current_slot)
  for val in 0 ..< min(self.votes.len, balance_source.balances.len):
    template balance: ForkChoiceBalance = balance_source.balances[val]
    template vote: VoteTracker = self.votes[val]
    if vote.slot != FAR_FUTURE_SLOT:
      # Collect support of the block per slot:
      # - get_block_support_between_slots (per slot, canonical only)
      #
      # Spec get_block_support_between_slots over-counts support
      # when a validator was assigned during an empty slot, but actually
      # voted for the root at a different slot (only assignment slot matters).
      # Deliberately ignoring vote.slot to match spec over-count
      var found = false
      let o = current_slot.epoch.shuffling_index
      for slot in balance_source.assigned_slots(val.ValidatorIndex, o):
        if slot in low_slot .. current_slot:
          let i = result.index(slot, current_slot)
          if vote.next_root == result[i].blck.root:
            result[i].support += balance.unslashed_balance
            found = true
            break

      # Collect noncanonical (and stale) support of the block:
      # - get_attestation_score (total, including non-canonical)
      if not found:
        let ancestor_i = noncanonical.getOrDefault(vote.next_root, -1)
        if ancestor_i != -1:
          result[ancestor_i].total_support += balance.unslashed_balance

    else:
      # Collect weight of equivocating participants:
      # - get_equivocation_score (per slot, between blocks)
      # - get_adversarial_weight (total, to current_slot)
      var old_i = -1
      let
        eb = balance.effective_balance
        o = current_slot.epoch.shuffling_index
      for slot in balance_source.assigned_slots(val.ValidatorIndex, o):
        if slot in low_slot ..< current_slot:
          let i = result.index(slot, current_slot)
          if old_i == -1 or result[i].blck != result[old_i].blck:
            result[i].adversarial += eb
            if old_i == -1:
              result[i].total_adversarial += eb
          old_i = i

  result[0].total_support += result[0].support
  for i in 1 ..< result.len:
    result[i].total_support += result[i].support + result[i - 1].total_support
    result[i].total_adversarial += result[i - 1].total_adversarial

func is_one_confirmed(
    chain: seq[SlotInfo], i: int, current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): bool =
  ## Return ``true`` if and only if the block is LMD-GHOST safe.
  true  # TODO

func is_confirmed_chain_safe(
    self: ForkChoiceBackend, dag: ChainDAGRef, current_slot: Slot): bool =
  ## Return ``true`` if and only if all blocks of the confirmed chain starting
  ## from current_epoch_observed_justified.checkpoint are LMD-GHOST safe.

  template balance_source: BalanceSource =
    # This is still get_previous_balance_source. Caller's responsibility
    # to update _after_ reconfirmation via update_unrealized_justified
    self.current_epoch_observed_justified

  template current_epoch_justified: Checkpoint =
    # This is what current_epoch_observed_justified.checkpoint will hold
    # after the balance source gets updated via update_unrealized_justified
    self.previous_epoch_greatest_unrealized_checkpoint

  # Exclude the justified checkpoint block if it is from the previous epoch
  # as then this block will always be canonical in this case.
  # Otherwise: Limit reconfirmation to the first block of the previous epoch
  # as if it's successful, reconfirmation of the ancestors is implied.
  let
    confirmed = dag.getBlockRef(self.confirmed.root).valueOr:
      return false
    current_justified = BlockId(
      slot: current_epoch_justified.epoch.start_slot,
      root: current_epoch_justified.root)
    chain = self.get_ancestor_support_by_slot(
      balance_source, dag.heads, confirmed, current_justified, current_slot)

  # Check if the confirmed.root is descendant of
  # current_epoch_observed_justified.checkpoint.
  if chain.len == 0:
    return false

  # Run is_one_confirmed for each block in the confirmed chain with the
  # previous epoch balance source.
  let
    total_active_balance = balance_source.total_active_balance
    byzantine_threshold = self.confirmation_byzantine_threshold
  for i in countdown(chain.high - 1, 0):
    if chain[i].blck == chain[i + 1].blck:
      continue
    if not chain.is_one_confirmed(
        i, current_slot, total_active_balance, byzantine_threshold):
      return false
  true

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

  not self.is_confirmed_chain_safe(dag, current_slot)

func should_revert_confirmed_on_new_head*(
    self: ForkChoiceBackend, blck: BlockRef, current_slot: Slot): bool =
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

func is_proto_array_consistent*(self: ForkChoiceBackend): bool =
  self.current_slot_head in self.proto_array and
  self.current_epoch_observed_justified.checkpoint.root in self.proto_array

func should_restart_confirmation_chain*(
    self: ForkChoiceBackend, current_slot: Slot): bool =
  # Restart the confirmation chain if each of the following conditions are true:
  # 1) it is the start of the current epoch,
  # 2) epoch of self.current_epoch_observed_justified.checkpoint equals to the
  #    previous epoch,
  # 3) self.current_epoch_observed_justified.checkpoint equals to unrealized
  #    justification of the head,
  # 4) confirmed block is older than the block of
  #    self.current_epoch_observed_justified.checkpoint.
  template current_epoch_justified: Checkpoint =
    self.current_epoch_observed_justified.checkpoint
  template current_epoch_justified_slot: Slot =
    self.proto_array.slot(current_epoch_justified.root)
      .expect("is_proto_array_consistent")

  template head_unrealized_justified: Checkpoint =
    self.proto_array.checkpoints(self.current_slot_head)
      .expect("is_proto_array_consistent").unrealized

  current_slot.is_epoch and
  current_epoch_justified.epoch + 1 == current_slot.epoch and
  current_epoch_justified == head_unrealized_justified and
  self.confirmed.slot < current_epoch_justified_slot

type CurrentTargetInfo* = object
  total_active_balance*: Gwei
  total_support*: Gwei
  total_adversarial*: Gwei

func all_current_target_descendants*(
    blck: BlockRef, heads: seq[BlockRef],
    current_slot: Slot): HashSet[Eth2Digest] =
  let target_slot = current_slot.epoch.start_slot
  var target = blck
  while target != nil and target.slot > target_slot:
    result.incl target.root
    target = target.parent
  if target != nil:
    result.incl target.root
  for head in heads:
    if head.atSlot(target_slot).blck == target:
      var blck = head
      while not result.containsOrIncl(blck.root):
        blck = blck.parent

func get_current_target_info*[T: Validator | ForkChoiceBalance](
    self: ForkChoiceBackend, roots: HashSet[Eth2Digest],
    shufflingRef: ShufflingRef, validators: seq[T],
    current_slot: Slot): CurrentTargetInfo =
  let current_epoch = current_slot.epoch
  for slot in current_slot.epoch.slots:
    for committee_index in get_committee_indices(shufflingRef):
      for _, val in shufflingRef.get_beacon_committee(slot, committee_index):
        if val < validators.lenu64:
          template validator: T = validators[val]
          let eb = validator.effective_balance
          result.total_active_balance += eb
          if val < self.votes.lenu64:
            template vote: VoteTracker = self.votes[val]
            if vote.slot.epoch == current_epoch and
                not validator.slashed and vote.next_root in roots:
              result.total_support += eb
            elif vote.slot == FAR_FUTURE_SLOT and slot < current_slot:
              result.total_adversarial += eb
            else:
              discard

proc get_current_target_info*(
    self: ForkChoiceBackend, dag: ChainDAGRef,
    blck: BlockRef, current_slot: Slot): Opt[CurrentTargetInfo] =
  ## Return the estimate of FFG support of the current epoch target
  ## by using LMD-GHOST votes.
  let
    current_epoch = current_slot.epoch
    shufflingRef = ? dag.getShufflingRef(blck, current_epoch, false)
    roots = blck.all_current_target_descendants(dag.heads, current_slot)

  template isCompatible(state: ForkedHashedBeaconState): bool =
    withState(state):
      forkyState.data.slot.epoch == current_epoch and
      forkyState.latest_block_root == blck.root

  let state =
    if dag.clearanceState.isCompatible:
      addr dag.clearanceState
    elif dag.headState.isCompatible:
      addr dag.headState
    elif dag.epochRefState.isCompatible:
      addr dag.epochRefState
    else:
      nil
  if state != nil:
    result.ok self.get_current_target_info(
      roots, shufflingRef, state[].validators, current_slot)
  else:
    let epochRef = dag.getEpochRef(blck, current_epoch, false).valueOr:
      return Opt.none CurrentTargetInfo
    result.ok self.get_current_target_info(
      roots, epochRef.shufflingRef, epochRef.fork_choice_balances, current_slot)
