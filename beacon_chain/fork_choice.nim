import
  deques, options, sequtils, tables,
  chronicles,
  ./spec/[datatypes, crypto, helpers],
  ./attestation_pool, ./beacon_node_types, ./ssz

proc get_ancestor(blck: BlockRef, slot: Slot): BlockRef =
  if blck.slot == slot:
    blck
  elif blck.slot < slot:
    nil
  else:
    get_ancestor(blck.parent, slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_fork-choice.md
# The structure of this code differs from the spec since we use a different
# strategy for storing states and justification points - it should nonetheless
# be close in terms of functionality.
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
        start_state, compute_epoch_at_slot(start_state.slot))

  var latest_messages: seq[tuple[validator: ValidatorIndex, blck: BlockRef]]
  for i in active_validator_indices:
    let pubKey = start_state.validators[i].pubkey
    if (let vote = pool.latestAttestation(pubKey); not vote.isNil):
      latest_messages.add((i, vote))

  template get_latest_attesting_balance(blck: BlockRef): uint64 =
    var res: uint64
    for validator_index, target in latest_messages.items():
      if get_ancestor(target, blck.slot) == blck:
        res += start_state.validators[validator_index].effective_balance
    res

  var head = start_block
  while true:
    if head.children.len() == 0:
      return head

    head = head.children[0]
    var
      headCount = get_latest_attesting_balance(head)

    for i in 1..<head.children.len:
      if (let hc  = get_latest_attesting_balance(head.children[i]); hc > headCount):
        head = head.children[i]
        headCount = hc
