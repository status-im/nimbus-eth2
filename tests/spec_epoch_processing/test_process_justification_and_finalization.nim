

# Justification and finalization utils
# ---------------------------------------------------------------

iterator getShardsForSlot(state: BeaconState, slot: Slot): Shard =
  let
    epoch = compute_epoch_of_slot(slot)
    epoch_start_shard = get_start_shard(state, epoch)
    committees_per_slot = get_committee_count(state, epoch) div SLOTS_PER_EPOCH
    shard = epoch_start_shard + committees_per_slot * (slot mod SLOTS_PER_EPOCH)

  for i in 0 ..< committees_per_slot:
    yield shard + i

