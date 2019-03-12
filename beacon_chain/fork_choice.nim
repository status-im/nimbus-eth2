import
  deques, options, sequtils, tables,
  chronicles,
  ./spec/[beaconstate, datatypes, crypto, digest, helpers, validator], extras,
  ./attestation_pool, ./beacon_node_types, ./beacon_chain_db, ./ssz

proc get_ancestor(blck: BlockRef, slot: Slot): BlockRef =
  if blck.slot == slot:
    blck
  elif blck.slot < slot:
    nil
  else:
    get_ancestor(blck.parent, slot)

proc lmdGhost*(
    pool: AttestationPool, start_state: BeaconState,
    start_block: BlockRef): BlockRef =
  # TODO: a Fenwick Tree datastructure to keep track of cumulated votes
  #       in O(log N) complexity
  #       https://en.wikipedia.org/wiki/Fenwick_tree
  #       Nim implementation for cumulative frequencies at
  #       https://github.com/numforge/laser/blob/990e59fffe50779cdef33aa0b8f22da19e1eb328/benchmarks/random_sampling/fenwicktree.nim

  let
    active_validator_indices =
      get_active_validator_indices(
        start_state.validator_registry, slot_to_epoch(start_state.slot))

  var attestation_targets: seq[tuple[validator: ValidatorIndex, blck: BlockRef]]
  for i in active_validator_indices:
    let pubKey = start_state.validator_registry[i].pubkey
    if (let vote = pool.latestAttestation(pubKey); not vote.isNil):
      attestation_targets.add((i, vote))

  proc get_vote_count(blck: BlockRef): uint64 =
    for validator_index, target in attestation_targets.items():
      if get_ancestor(target, blck.slot) == blck:
        result += get_effective_balance(start_state, validator_index) div
            FORK_CHOICE_BALANCE_INCREMENT

  var head = start_block
  while true:
    let children = head.children
    if children.len() == 0:
      return head
    var
      head = children[0]
      headCount = get_vote_count(head)

    for i in 1..children.len:
      if (let hc  = get_vote_count(children[i]); hc > headCount):
        head = children[i]
        headCount = hc
