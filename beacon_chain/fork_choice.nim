import
  deques, options, sequtils, tables,
  chronicles,
  ./spec/[beaconstate, datatypes, crypto, digest, helpers, validator], extras,
  ./attestation_pool, ./beacon_chain_db, ./ssz

# ##################################################################
# Specs
#
#   The beacon chain fork choice rule is a hybrid that combines justification and finality with Latest Message Driven (LMD) Greediest Heaviest Observed SubTree (GHOST). At any point in time a [validator](#dfn-validator) `v` subjectively calculates the beacon chain head as follows.
#
#      * Let `store` be the set of attestations and blocks
#        that the validator `v` has observed and verified
#        (in particular, block ancestors must be recursively verified).
#        Attestations not part of any chain are still included in `store`.
#      * Let `finalized_head` be the finalized block with the highest slot number.
#        (A block `B` is finalized if there is a descendant of `B` in `store`
#        the processing of which sets `B` as finalized.)
#      * Let `justified_head` be the descendant of `finalized_head`
#        with the highest slot number that has been justified
#        for at least `EPOCH_LENGTH` slots.
#        (A block `B` is justified if there is a descendant of `B` in `store`
#        the processing of which sets `B` as justified.)
#        If no such descendant exists set `justified_head` to `finalized_head`.
#      * Let `get_ancestor(store, block, slot)` be the ancestor of `block` with slot number `slot`.
#        The `get_ancestor` function can be defined recursively
#
#        def get_ancestor(store, block, slot):
#            return block if block.slot == slot
#                         else get_ancestor(store, store.get_parent(block), slot)`.
#
#      * Let `get_latest_attestation(store, validator)`
#        be the attestation with the highest slot number in `store` from `validator`.
#        If several such attestations exist,
#        use the one the validator `v` observed first.
#      * Let `get_latest_attestation_target(store, validator)`
#        be the target block in the attestation `get_latest_attestation(store, validator)`.
#      * The head is `lmd_ghost(store, justified_head)`. (See specs)
#
# Departing from specs:
#   - We use a simple fork choice rule without finalized and justified head
#   - We don't implement "get_latest_attestation(store, validator) -> Attestation"
#     nor get_latest_attestation_target
#   - We use block hashes (Eth2Digest) instead of raw blocks where possible

proc get_parent(db: BeaconChainDB, blck: Eth2Digest): Eth2Digest =
  db.getBlock(blck).parent_root

proc get_ancestor(
    store: BeaconChainDB, blck: Eth2Digest, slot: SlotNumber): Eth2Digest =
  ## Find the ancestor with a specific slot number
  let blk = store.getBlock(blck)
  if blk.slot == slot:
    blck
  else:
    store.get_ancestor(blk.parent_root, slot) # TODO: Eliminate recursion
  # TODO: what if the slot was never observed/verified?

func getVoteCount(aggregation_bitfield: openarray[byte]): int =
  ## Get the number of votes
  # TODO: A bitfield type that tracks that information
  # https://github.com/status-im/nim-beacon-chain/issues/19

  for validatorIdx in 0 ..< aggregation_bitfield.len * 8:
    result += int aggregation_bitfield.get_bitfield_bit(validatorIdx)

func getAttestationVoteCount(
    pool: AttestationPool, current_slot: SlotNumber): CountTable[Eth2Digest] =
  ## Returns all blocks more recent that the current slot
  ## that were attested and their vote count
  # This replaces:
  #   - get_latest_attestation,
  #   - get_latest_attestation_targets
  # that are used in lmd_ghost for
  # ```
  # attestation_targets = [get_latest_attestation_target(store, validator)
  #                        for validator in active_validators]
  # ```
  # Note that attestation_targets in the Eth2 specs can have duplicates
  # while the following implementation will count such blockhash multiple times instead.
  result = initCountTable[Eth2Digest]()

  # TODO iteration API that hides the startingSlot logic?
  for slot in current_slot - pool.startingSlot ..< pool.slots.len.uint64:
    for attestation in pool.slots[slot].attestations:
      for validation in attestation.validations:
        # Increase the block attestation counts by the number of validators aggregated
        let voteCount = validation.aggregation_bitfield.getVoteCount()
        result.inc(attestation.data.beacon_block_root, voteCount)

proc lmdGhost*(
      store: BeaconChainDB,
      pool: AttestationPool,
      state: BeaconState,
      blocksChildren: Table[Eth2Digest, seq[Eth2Digest]]): BeaconBlock =
  # Recompute the new head of the beacon chain according to
  # LMD GHOST (Latest Message Driven - Greediest Heaviest Observed SubTree)

  # Raw vote count from all attestations
  let rawVoteCount = pool.getAttestationVoteCount(state.slot)

  # The real vote count for a block also takes into account votes for its children

  # TODO: a Fenwick Tree datastructure to keep track of cumulated votes
  #       in O(log N) complexity
  #       https://en.wikipedia.org/wiki/Fenwick_tree
  #       Nim implementation for cumulative frequencies at
  #       https://github.com/numforge/laser/blob/990e59fffe50779cdef33aa0b8f22da19e1eb328/benchmarks/random_sampling/fenwicktree.nim

  var head = state.latest_block_roots[state.slot mod LATEST_BLOCK_ROOTS_LENGTH]
  var childVotes = initCountTable[Eth2Digest]()

  while true: # TODO use a O(log N) implementation instead of O(N^2)
    let children = blocksChildren[head]
    if children.len == 0:
      return store.getBlock(head)

    # For now we assume that all children are direct descendant of the current head
    let next_slot = store.getBlock(head).slot + 1
    for child in children:
      doAssert store.getBlock(child).slot == next_slot

    childVotes.clear()
    for target, votes in rawVoteCount.pairs:
      if store.getBlock(target).slot >= next_slot:
        childVotes.inc(store.get_ancestor(target, next_slot), votes)

    head = childVotes.largest().key
