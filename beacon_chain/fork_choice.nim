import
  deques, options, tables,
  ./spec/[datatypes, crypto, digest, helpers, validator], extras,
  ./beacon_chain_db

type
  AttestationCandidate* = object
    validator*: int
    data*: AttestationData
    signature*: ValidatorSig

  AttestationPool* = object
    # The Deque below stores all outstanding attestations per slot.
    # In each slot, we have an array of all attestations indexed by their
    # shard number. When we haven't received an attestation for a particular
    # shard yet, the Option value will be `none`
    attestations: Deque[array[SHARD_COUNT, Option[Attestation]]]
    startingSlot: int

  # TODO:
  # The compilicated Deque above is not needed.
  #
  # In fact, we can use a simple array with length SHARD_COUNT because
  # in each epoch, each shard is going to receive attestations exactly once.
  # Once the epoch is over, we can discard all attestations and start all
  # over again (no need for `discardHistoryToSlot` too).

proc init*(T: type AttestationPool, startingSlot: int): T =
  result.attestations = initDeque[array[SHARD_COUNT, Option[Attestation]]]()
  result.startingSlot = startingSlot

proc setLen*[T](d: var Deque[T], len: int) =
  # TODO: The upstream `Deque` type should gain a proper resize API
  let delta = len - d.len
  if delta > 0:
    for i in 0 ..< delta:
      var defaultVal: T
      d.addLast(defaultVal)
  else:
    d.shrink(fromLast = delta)

proc combine*(tgt: var Attestation, src: Attestation, flags: UpdateFlags) =
  # Combine the signature and participation bitfield, with the assumption that
  # the same data is being signed!
  # TODO similar code in work_pool, clean up

  assert tgt.data == src.data

  for i in 0 ..< tgt.aggregation_bitfield.len:
    # TODO:
    # when BLS signatures are combined, we must ensure that
    # the same participant key is not included on both sides
    tgt.aggregation_bitfield[i] =
      tgt.aggregation_bitfield[i] or
      src.aggregation_bitfield[i]

  if skipValidation notin flags:
    tgt.aggregate_signature.combine(src.aggregate_signature)

proc add*(pool: var AttestationPool,
          attestation: Attestation,
          beaconState: BeaconState) =
  # The caller of this function is responsible for ensuring that
  # the attestations will be given in a strictly slot increasing order:
  doAssert attestation.data.slot.int >= pool.startingSlot

  # TODO:
  # Validate that the attestation is authentic (it's properly signed)
  # and make sure that the validator is supposed to make an attestation
  # for the specific shard/slot

  let slotIdxInPool = attestation.data.slot.int - pool.startingSlot
  if slotIdxInPool >= pool.attestations.len:
    pool.attestations.setLen(slotIdxInPool + 1)

  let shard = attestation.data.shard

  if pool.attestations[slotIdxInPool][shard].isSome:
    combine(pool.attestations[slotIdxInPool][shard].get, attestation, {})
  else:
    pool.attestations[slotIdxInPool][shard] = some(attestation)

proc getAttestationsForBlock*(pool: AttestationPool,
                              lastState: BeaconState,
                              newBlockSlot: uint64): seq[Attestation] =
  if newBlockSlot < MIN_ATTESTATION_INCLUSION_DELAY or pool.attestations.len == 0:
    return

  doAssert newBlockSlot > lastState.slot

  var
    firstSlot = 0.uint64
    lastSlot = newBlockSlot - MIN_ATTESTATION_INCLUSION_DELAY

  if pool.startingSlot.uint64 + MIN_ATTESTATION_INCLUSION_DELAY <= lastState.slot:
    firstSlot = lastState.slot - MIN_ATTESTATION_INCLUSION_DELAY

  for slot in firstSlot .. lastSlot:
    let slotDequeIdx = slot.int - pool.startingSlot
    if slotDequeIdx >= pool.attestations.len: return
    let shardAndComittees = get_shard_committees_at_slot(lastState, slot)
    for s in shardAndComittees:
      if pool.attestations[slotDequeIdx][s.shard].isSome:
        result.add pool.attestations[slotDequeIdx][s.shard].get

proc discardHistoryToSlot*(pool: var AttestationPool, slot: int) =
  ## The index is treated inclusively
  let slot = slot - MIN_ATTESTATION_INCLUSION_DELAY.int
  if slot < pool.startingSlot:
    return
  let slotIdx = int(slot - pool.startingSlot)
  pool.attestations.shrink(fromFirst = slotIdx + 1)

func getAttestationCandidate*(attestation: Attestation): AttestationCandidate =
  # TODO: not complete AttestationCandidate object
  result.data = attestation.data
  result.signature = attestation.aggregate_signature

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

proc get_ancestor(store: BeaconChainDB, blck: Eth2Digest, slot: uint64): Eth2Digest =
  ## Find the ancestor with a specific slot number
  let blk = store.getBlock(blck)
  if blk.slot == slot:
    blck
  else:
    store.get_ancestor(blk.parent_root, slot) # TODO: Eliminate recursion
  # TODO: what if the slot was never observed/verified?

func getVoteCount(participation_bitfield: openarray[byte]): int =
  ## Get the number of votes
  # TODO: A bitfield type that tracks that information
  # https://github.com/status-im/nim-beacon-chain/issues/19

  for validatorIdx in 0 ..< participation_bitfield.len * 8:
    result += int participation_bitfield.get_bitfield_bit(validatorIdx)

func getAttestationVoteCount(pool: AttestationPool, current_slot: int): CountTable[Eth2Digest] =
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

  for slot in current_slot - pool.startingSlot ..< pool.attestations.len:
    for attestation in pool.attestations[slot]:
      if attestation.isSome:
        # Increase the block attestation counts by the number of validators aggregated
        let voteCount = attestation.get.aggregation_bitfield.getVoteCount()
        result.inc(attestation.get.data.beacon_block_root, voteCount)

proc lmdGhost*(
      store: BeaconChainDB,
      pool: AttestationPool,
      state: BeaconState,
      blocksChildren: Table[Eth2Digest, seq[Eth2Digest]]): BeaconBlock =
  # Recompute the new head of the beacon chain according to
  # LMD GHOST (Latest Message Driven - Greediest Heaviest Observed SubTree)

  # Raw vote count from all attestations
  let rawVoteCount = pool.getAttestationVoteCount(state.slot.int)

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
