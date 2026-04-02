# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sets, tables], stew/bitops2, chronicles,
  ../consensus_object_pools/spec_cache,
  "."/[fork_choice_types, proto_array]

from ../consensus_object_pools/blockchain_dag import
  ForkChoiceInfoOffset, fork_choice_balances,
  slashed, effective_balance, unslashed_balance,
  getBlockIdAtSlot, getBlockRef, getEpochRef, getShufflingRef

from ../spec/beaconstate import latest_block_root

export fork_choice_types

# FCR research paper: https://arxiv.org/abs/2405.00549
# Primary spec PR: https://github.com/ethereum/consensus-specs/pull/4747

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
    blck: BlockRef, current_slot: Slot): FcResult[void] =
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
          let bsi = dag.getBlockIdAtSlot(dependent_slot).valueOr:
            return err ForkChoiceError(
              kind: fcUnknownBlockIdAtSlot,
              shufflingRoot: blck.bid.root,
              shufflingEpoch: epoch)
          bsi.bid.root
      shufflingRef =
        if balance_source.has_shuffling(epoch, dependent_root):
          return ok()
        else:
          dag.getShufflingRef(blck, epoch, preFinalized = true).valueOr:
            return err ForkChoiceError(
              kind: fcUnknownShufflingRef,
              shufflingRoot: blck.bid.root,
              shufflingEpoch: epoch)
    balance_source.record_shuffling(shufflingRef)
    if epoch <= GENESIS_EPOCH:
      return ok()
    dec epoch
  ok()

proc update_latest_shufflings(
    balance_source: var BalanceSource, dag: ChainDAGRef,
    blck: BlockRef, current_slot: Slot): FcResult[void] =
  result = balance_source.do_update_shufflings(dag, blck, current_slot)
  if result.isErr:
    balance_source.shuffling_epochs = DefaultShufflingEpochs

proc update_latest_shufflings*(
    balance_source: var BalanceSource, dag: ChainDAGRef,
    current_slot: Slot): FcResult[void] =
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

func get_block_support_between_slots(
    chain: seq[SlotInfo], slots: Slice[Slot], current_slot: Slot): Gwei =
  ## Return support of the block within ``slots``.
  let
    a = chain.index(slots.a, current_slot)
    b = chain.index(slots.b, current_slot)
  for i in b .. a:
    result += chain[i].support

func is_full_validator_set_covered(slots: Slice[Slot]): bool =
  ## Return ``true`` if the range within ``slots`` includes an entire epoch.
  let
    start_full_epoch = (slots.a + (SLOTS_PER_EPOCH - 1)).epoch
    end_full_epoch = (slots.b + 1).epoch

  start_full_epoch < end_full_epoch

func adjust_committee_weight_estimate_to_ensure_safety(estimate: Gwei): Gwei =
  ## Return adjusted ``estimate`` of the weight of a committee for a sequence
  ## of slots not covering a full epoch.
  # Per mille value to add to the estimation of the committee weight across a
  # range of slots not covering a full epoch in order to ensure the safety of
  # the confirmation rule with high probability.
  # See https://gist.github.com/saltiniroberto/9ee53d29c33878d79417abb2b4468c20
  # for an explanation about the value chosen.
  const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR = 5'u64
  estimate div 1000 * (1000 + COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR)

func estimate_committee_weight_between_slots(
    total_active_balance: Gwei, slots: Slice[Slot]): Gwei =
  ## Return estimate of the total weight of committees within ``slots``.

  # Sanity check
  if slots.a > slots.b:
    return 0.Gwei

  # If an entire epoch is covered by the range, return the total active balance
  if is_full_validator_set_covered(slots):
    return total_active_balance

  let
    start_epoch = slots.a.epoch
    end_epoch = slots.b.epoch
    committee_weight = total_active_balance div SLOTS_PER_EPOCH
  if start_epoch == end_epoch:
    committee_weight * (slots.b - slots.a + 1)
  else:
    let
      # First, calculate the number of committees in the end epoch
      num_slots_in_end_epoch = slots.b.since_epoch_start + 1
      # Next, calculate the number of slots remaining in the end epoch
      remaining_slots_in_end_epoch = SLOTS_PER_EPOCH - num_slots_in_end_epoch
      # Then, calculate the number of slots in the start epoch
      num_slots_in_start_epoch = SLOTS_PER_EPOCH - slots.a.since_epoch_start

      start_epoch_weight = committee_weight * num_slots_in_start_epoch
      end_epoch_weight = committee_weight * num_slots_in_end_epoch

      # A range that spans an epoch boundary, but does not span any full epoch
      # needs pro-rata calculation, see
      # https://gist.github.com/saltiniroberto/9ee53d29c33878d79417abb2b4468c20
      # start_epoch_weight_pro_rated =
      #   start_epoch_weight * (1 - num_slots_in_end_epoch / SLOTS_PER_EPOCH)
      start_epoch_weight_pro_rated =
        start_epoch_weight div SLOTS_PER_EPOCH * remaining_slots_in_end_epoch

    adjust_committee_weight_estimate_to_ensure_safety(
      start_epoch_weight_pro_rated + end_epoch_weight)

func get_equivocation_score(
    chain: seq[SlotInfo], slots: Slice[Slot], current_slot: Slot): Gwei =
  ## Return total weight of equivocating participants of all committees
  ## in the slots within ``slots``.
  let
    a = chain.index(slots.a, current_slot)
    b = chain.index(slots.b, current_slot)
  for i in b .. a:
    result += chain[i].adversarial

func compute_adversarial_weight(
    equivocation_score: Gwei, slots: Slice[Slot],
    total_active_balance: Gwei, byzantine_threshold: uint64): Gwei =
  ## Return maximum possible adversarial weight in the committees of the slots
  ## within ``slots``.
  let
    maximum_weight = estimate_committee_weight_between_slots(
      total_active_balance, slots)
    max_adversarial_weight = maximum_weight div 100 * byzantine_threshold

  # Discount total weight of equivocating validators.
  if max_adversarial_weight > equivocation_score:
    max_adversarial_weight - equivocation_score
  else:
    0.Gwei

func compute_adversarial_weight(
    chain: seq[SlotInfo], slots: Slice[Slot], current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): Gwei =
  ## Return maximum possible adversarial weight in the committees of the slots
  ## within ``slots``.
  let equivocation_score = chain.get_equivocation_score(slots, current_slot)
  equivocation_score.compute_adversarial_weight(
    slots, total_active_balance, byzantine_threshold)

func compute_adversarial_weight(
    chain: seq[SlotInfo], start_slot, current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): Gwei =
  ## Return maximum possible adversarial weight in the committees of the slots
  ## between ``start_slot`` and ``current_slot - 1`` (inclusive of both).
  let
    i = chain.index(start_slot, current_slot)
    equivocation_score = chain[i].total_adversarial
  equivocation_score.compute_adversarial_weight(
    start_slot ..< current_slot, total_active_balance, byzantine_threshold)

func get_adversarial_weight(
    chain: seq[SlotInfo], i: int, current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): Gwei =
  ## Return maximum adversarial weight that can support the block.
  let start_slot =
    if chain[i].blck.slot.epoch > chain[i + 1].blck.slot.epoch:
      # Use the first epoch slot as the start slot when crossing epoch boundary.
      chain[i].blck.slot.epoch.start_slot
    else:
      chain[i].blck.slot
  chain.compute_adversarial_weight(
    start_slot, current_slot, total_active_balance, byzantine_threshold)

func compute_empty_slot_support_discount(
    chain: seq[SlotInfo], i: int, current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): Gwei =
  ## Return weight that can be discounted during the safety threshold
  ## computation if there are empty slots preceding the block.

  let parent_blck = chain[i + 1].blck
  # No empty slot.
  if parent_blck.slot + 1 == chain[i].blck.slot:
    return 0.Gwei

  let
    empty_slots = parent_blck.slot + 1 ..< chain[i].blck.slot
    # Discount votes supporting the parent block if they are from
    # the committees of empty slots.
    parent_support_in_empty_slots = chain.get_block_support_between_slots(
      empty_slots, current_slot)
    # Adversarial weight is not discounted.
    adversarial_weight = chain.compute_adversarial_weight(
      empty_slots, current_slot, total_active_balance, byzantine_threshold)
  if parent_support_in_empty_slots > adversarial_weight:
    parent_support_in_empty_slots - adversarial_weight
  else:
    0.Gwei

func get_support_discount(
    chain: seq[SlotInfo], i: int, current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): Gwei =
  ## Return weight that can be discounted during the safety threshold
  ## computation for the block.

  # Empty slot support discount
  chain.compute_empty_slot_support_discount(
    i, current_slot, total_active_balance, byzantine_threshold)

func compute_safety_threshold(
    chain: seq[SlotInfo], i: int, current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): Gwei =
  ## Compute the LMD_GHOST safety threshold for ``chain[i].blck.root``.
  let
    parent_blck = chain[i + 1].blck

    proposer_score = compute_proposer_score(total_active_balance)
    maximum_support = estimate_committee_weight_between_slots(
      total_active_balance, parent_blck.slot + 1 ..< current_slot)
    support_discount = chain.get_support_discount(
      i, current_slot, total_active_balance, byzantine_threshold)
    adversarial_weight = chain.get_adversarial_weight(
      i, current_slot, total_active_balance, byzantine_threshold)

    # Return (maximum_support + proposer_score - support_discount) // 2 +
    # adversarial_weight with an underflow guard
    threshold = maximum_support + proposer_score + 2 * adversarial_weight
  if support_discount < threshold:
    (threshold - support_discount) div 2
  else:
    0.Gwei

func is_one_confirmed(
    chain: seq[SlotInfo], i: int, current_slot: Slot,
    total_active_balance: Gwei, byzantine_threshold: uint64): bool =
  ## Return ``true`` if and only if the block is LMD-GHOST safe.
  if chain[i].blck.optimisticStatus != OptimisticStatus.valid:
    return false  # Do not confirm optimistically imported / invalid blocks

  let
    support = chain[i].total_support
    safety_threshold = chain.compute_safety_threshold(
      i, current_slot, total_active_balance, byzantine_threshold)

  support > safety_threshold

type FcrDiagnostics* = object
  chain_len*: int
  failed_block*: BlockId
  support*: Gwei
  safety_threshold*: Gwei
  total_active_balance*: Gwei
  byzantine_threshold*: uint64

func `$`*(diag: FcrDiagnostics): string =
  shortLog(diag.failed_block) & ": " &
  formatGwei(diag.support) & " <= " &
  formatGwei(diag.safety_threshold) & " (" &
  formatGwei(diag.total_active_balance) & " total, " &
  $diag.byzantine_threshold & "% byz, " &
  $diag.chain_len & " blks)"

chronicles.formatIt FcrDiagnostics: $it

func is_confirmed_chain_safe(
    self: ForkChoiceBackend, dag: ChainDAGRef, confirmed: BlockId,
    current_slot: Slot, diag: var FcrDiagnostics): FcResult[bool] =
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
    confirmed = dag.getBlockRef(confirmed.root).valueOr:
      return err ForkChoiceError(
        kind: fcConfirmedNodeUnknown,
        blockRoot: confirmed.root)
    current_justified = BlockId(
      slot: current_epoch_justified.epoch.start_slot,
      root: current_epoch_justified.root)
    chain = self.get_ancestor_support_by_slot(
      balance_source, dag.heads, confirmed, current_justified, current_slot)

  # Check if the confirmed.root is descendant of
  # current_epoch_observed_justified.checkpoint.
  if chain.len == 0:
    return ok false

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
      diag = FcrDiagnostics(
        chain_len: chain.len,
        failed_block: chain[i].blck.bid,
        support: chain[i].total_support,
        safety_threshold: chain.compute_safety_threshold(
          i, current_slot, total_active_balance, byzantine_threshold),
        total_active_balance: total_active_balance,
        byzantine_threshold: byzantine_threshold)
      return ok false
  ok true

proc should_revert_confirmed_on_new_epoch*(
    self: var ForkChoiceBackend, dag: ChainDAGRef, confirmed: BlockId,
    current_slot: Slot, diag: var FcrDiagnostics): FcResult[bool] =
  # Revert to finalized block if either of the following is true:
  # 1) the latest confirmed block's epoch is older than the previous epoch,
  # 2) [...],
  # 3) the confirmed chain starting from the current epoch observed justified
  #    checkpoint cannot be re-confirmed at the start of the current epoch.
  if confirmed.slot.epoch + 1 < current_slot.epoch:
    return ok true

  template balance_source: BalanceSource = self.current_epoch_observed_justified
  ? balance_source.update_latest_shufflings(dag, current_slot)

  ok not ? self.is_confirmed_chain_safe(dag, confirmed, current_slot, diag)

func should_revert_confirmed_on_new_head*(
    self: ForkChoiceBackend, blck: BlockRef,
    confirmed: BlockId, current_slot: Slot): FcResult[bool] =
  # Revert to finalized block if either of the following is true:
  # 1) [...],
  # 2) the latest confirmed block doesn't belong to the canonical chain,
  # 3) [...].
  if confirmed.slot.epoch + 1 < current_slot.epoch:
    return ok true

  var blck = blck
  while blck != nil and blck.slot > confirmed.slot:
    blck = blck.parent
  ok(blck == nil or blck.root != confirmed.root)

func should_restart_confirmation_chain*(
    self: ForkChoiceBackend,
    confirmed: BlockId, current_slot: Slot): FcResult[bool] =
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
    self.proto_array.slot(current_epoch_justified.root).valueOr:
      return err ForkChoiceError(
        kind: fcJustifiedNodeUnknown,
        blockRoot: current_epoch_justified.root)

  template head_unrealized_justified: Checkpoint =
    self.proto_array.unrealized_justified(self.current_slot_head).valueOr:
      return err ForkChoiceError(
        kind: fcCurrentHeadUnknown,
        blockRoot: self.current_slot_head)

  ok(current_slot.is_epoch and
    current_epoch_justified.epoch + 1 == current_slot.epoch and
    current_epoch_justified == head_unrealized_justified and
    confirmed.slot < current_epoch_justified_slot)

func get_current_target(blck: BlockRef, current_slot: Slot): Checkpoint =
  ## Return current epoch target.
  let current_epoch = current_slot.epoch
  Checkpoint(
    epoch: current_epoch,
    root: blck.atSlot(current_epoch.start_slot).blck.root)

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
    blck: BlockRef, current_slot: Slot): FcResult[CurrentTargetInfo] =
  ## Return the estimate of FFG support of the current epoch target
  ## by using LMD-GHOST votes.
  let
    current_epoch = current_slot.epoch
    shufflingRef = dag.getShufflingRef(blck, current_epoch, false).valueOr:
      return err ForkChoiceError(
        kind: fcUnknownShufflingRef,
        shufflingRoot: blck.root,
        shufflingEpoch: current_epoch)
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
      return err ForkChoiceError(
        kind: fcUnknownShufflingRef,
        shufflingRoot: blck.root,
        shufflingEpoch: current_epoch)
    result.ok self.get_current_target_info(
      roots, epochRef.shufflingRef, epochRef.fork_choice_balances, current_slot)

func compute_honest_ffg_support_for_current_target(
    info: CurrentTargetInfo, current_slot: Slot,
    byzantine_threshold: uint64): Gwei =
  ## Compute honest FFG support of the current epoch target.
  let
    slots = current_slot.epoch.start_slot ..< current_slot

    # Compute FFG support for the target
    ffg_support_for_checkpoint = info.total_support

    # Compute total FFG weight till current slot exclusive
    ffg_weight_till_now = estimate_committee_weight_between_slots(
      info.total_active_balance, slots)

    # Compute remaining honest FFG weight
    remaining_ffg_weight = info.total_active_balance - ffg_weight_till_now
    remaining_honest_ffg_weight =
      remaining_ffg_weight div 100 * (100 - byzantine_threshold)

    # Compute potential adversarial weight
    adversarial_weight = info.total_adversarial.compute_adversarial_weight(
      slots, info.total_active_balance, byzantine_threshold)

    # Compute min honest FFG support
    min_honest_ffg_support = ffg_support_for_checkpoint -
      min(adversarial_weight, ffg_support_for_checkpoint)

  min_honest_ffg_support + remaining_honest_ffg_weight

func will_no_conflicting_checkpoint_be_justified(
    info: CurrentTargetInfo, blck: BlockRef, unrealized: Checkpoint,
    current_slot: Slot, byzantine_threshold: uint64): bool =
  ## Return ``true`` if and only if no checkpoint conflicting with the
  ## current target can ever be justified.

  # If the target is unrealized justified then no conflicting checkpoint
  # can be justified.
  if blck.get_current_target(current_slot) == unrealized:
    return true

  let honest_ffg_support = info.compute_honest_ffg_support_for_current_target(
    current_slot, byzantine_threshold)
  3 * honest_ffg_support > 1 * info.total_active_balance

func will_current_target_be_justified(
    info: CurrentTargetInfo,
    current_slot: Slot, byzantine_threshold: uint64): bool =
  ## Return ``true`` if and only if the current target will eventually
  ## be justified.
  let honest_ffg_support = info.compute_honest_ffg_support_for_current_target(
    current_slot, byzantine_threshold)
  3 * honest_ffg_support >= 2 * info.total_active_balance

proc find_latest_confirmed_descendant*(
    self: var ForkChoiceBackend, dag: ChainDAGRef,
    blck: BlockRef, unrealized: Checkpoint,
    confirmed: BlockId, current_slot: Slot): FcResult[BlockId] =
  ## Return the most recent confirmed block in the suffix of the canonical chain
  ## starting from ``confirmed.root``.

  template balance_source: BalanceSource =
    self.current_epoch_observed_justified

  let
    current_epoch = current_slot.epoch
    total_active_balance = balance_source.total_active_balance
    byzantine_threshold = self.confirmation_byzantine_threshold
    previous = self.proto_array.checkpoints(self.previous_slot_head).valueOr:
      return err ForkChoiceError(
        kind: fcPreviousHeadUnknown,
        blockRoot: self.previous_slot_head)
    current = self.proto_array.checkpoints(self.current_slot_head).valueOr:
      return err ForkChoiceError(
        kind: fcCurrentHeadUnknown,
        blockRoot: self.current_slot_head)

  var stored_info: Opt[CurrentTargetInfo]
  template info: lent CurrentTargetInfo =
    if stored_info.isNone:
      stored_info.ok(? self.get_current_target_info(dag, blck, current_slot))
    stored_info.unsafeGet

  var stored_no_conflict: Opt[bool]
  template will_no_conflicting_be_justified: bool =
    if stored_no_conflict.isNone:
      stored_no_conflict.ok info.will_no_conflicting_checkpoint_be_justified(
        blck, unrealized, current_slot, byzantine_threshold)
    stored_no_conflict.unsafeGet

  var
    stored_chain: Opt[seq[SlotInfo]]
    confirmed_i = -1
  template chain: lent seq[SlotInfo] = stored_chain.unsafeGet
  template init_chain =
    if stored_chain.isNone:
      ? balance_source.update_latest_shufflings(dag, blck, current_slot)
      stored_chain.ok self.get_ancestor_support_by_slot(
        balance_source, dag.heads, blck, confirmed, current_slot)
      confirmed_i = chain.high

  result.ok confirmed
  if confirmed.slot.epoch + 1 == current_epoch and
      previous.voting_source.epoch + 2 >= current_epoch and (
        current_slot.is_epoch or (
          will_no_conflicting_be_justified and (
            previous.unrealized_justified.epoch + 1 >= current_epoch or
            current.unrealized_justified.epoch + 1 >= current_epoch))):
    # Get suffix of the canonical chain
    init_chain()

    if chain.len > 0:
      # The algorithm can only rely on the previous head
      # if it is a descendant of the block that is attempted to be confirmed
      var
        blck = dag.getBlockRef(self.previous_slot_head).valueOr:
          return err ForkChoiceError(
            kind: fcPreviousHeadUnknown,
            blockRoot: self.previous_slot_head)
        j = chain.index(blck.slot, current_slot)
      while j < chain.high and chain[j].blck != blck:
        blck = blck.parent
        j =
          if blck != nil:
            chain.index(blck.slot, current_slot)
          else:
            chain.high

      # If the current epoch is reached, exit the loop
      # as this code is meant to confirm blocks from the previous epoch
      let prev_epoch_end = max(current_epoch, 1.Epoch).start_slot - 1
      j = max(j, chain.index(prev_epoch_end, current_slot))

      # Starting with the child of the latest_confirmed_root
      # move towards the head in attempt to advance confirmed block
      # and stop when the first unconfirmed descendant is encountered
      for i in countdown(confirmed_i - 1, j):
        if chain[i].blck == chain[i + 1].blck:
          continue
        if not chain.is_one_confirmed(
            i, current_slot, total_active_balance, byzantine_threshold):
          break
        result.ok chain[i].blck.bid
        confirmed_i = i

  if current_slot.is_epoch or
      current.unrealized_justified.epoch + 1 >= current_epoch:
    # Get suffix of the canonical chain
    init_chain()

    var tentative_confirmed = result.unsafeGet

    for i in countdown(confirmed_i - 1, 0):
      if chain[i].blck == chain[i + 1].blck:
        continue
      let
        block_epoch = chain[i].blck.slot.epoch
        tentative_confirmed_epoch = tentative_confirmed.slot.epoch

      # The following condition can only be true the first time
      # the algorithm advances to a block from the current epoch
      if block_epoch > tentative_confirmed_epoch:
        # To confirm blocks from the current epoch ensure that
        # current epoch target will be justified
        if not info.will_current_target_be_justified(
            current_slot, byzantine_threshold):
          break

      if not chain.is_one_confirmed(
          i, current_slot, total_active_balance, byzantine_threshold):
        break

      tentative_confirmed = chain[i].blck.bid

    # The tentative_confirmed.root can only be confirmed if it is for sure
    # not going to be reorged out in either the current or next epoch.
    template tentative_voting_source: Checkpoint =
      self.proto_array.voting_source(tentative_confirmed.root).valueOr:
        return err ForkChoiceError(
          kind: fcConfirmedNodeUnknown,
          blockRoot: tentative_confirmed.root)
    if tentative_confirmed.slot.epoch == current_epoch or (
        tentative_voting_source.epoch + 2 >= current_epoch and (
          current_slot.is_epoch or
          will_no_conflicting_be_justified)):
      result.ok tentative_confirmed
