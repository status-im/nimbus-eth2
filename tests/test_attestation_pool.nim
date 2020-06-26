# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  ../beacon_chain/spec/datatypes,
  ../beacon_chain/ssz

import
  unittest,
  chronicles,
  stew/byteutils,
  ./testutil, ./testblockutil,
  ../beacon_chain/spec/[digest, validator, state_transition, helpers, beaconstate],
  ../beacon_chain/[beacon_node_types, attestation_pool, block_pool, extras],
  ../beacon_chain/fork_choice/[fork_choice_types, fork_choice]

template wrappedTimedTest(name: string, body: untyped) =
  # `check` macro takes a copy of whatever it's checking, on the stack!
  block: # Symbol namespacing
    proc wrappedTest() =
      timedTest name:
        body
    wrappedTest()

suiteReport "Attestation pool processing" & preset():
  ## For now just test that we can compile and execute block processing with
  ## mock data.

  setup:
    # Genesis state that results in 3 members per committee
    var
      blockPool = newClone(BlockPool.init(makeTestDB(SLOTS_PER_EPOCH * 3)))
      pool = newClone(AttestationPool.init(blockPool[]))
      state = newClone(loadTailState(blockPool[]))
    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(state.data, state.data.data.slot + 1)

  timedTest "Can add and retrieve simple attestation" & preset():
    var cache = get_empty_per_epoch_cache()
    let
      # Create an attestation for slot 1!
      beacon_committee = get_beacon_committee(
        state.data.data, state.data.data.slot, 0.CommitteeIndex, cache)
      attestation = makeAttestation(
        state.data.data, state.blck.root, beacon_committee[0], cache)

    pool[].addAttestation(attestation)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations may arrive in any order" & preset():
    var cache = get_empty_per_epoch_cache()
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state.data.data, state.data.data.slot, 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(
        state.data.data, state.blck.root, bc0[0], cache)

    check:
      process_slots(state.data, state.data.data.slot + 1)

    let
      bc1 = get_beacon_committee(state.data.data,
        state.data.data.slot, 0.CommitteeIndex, cache)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, bc1[0], cache)

    # test reverse order
    pool[].addAttestation(attestation1)
    pool[].addAttestation(attestation0)

    discard process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations should be combined" & preset():
    var cache = get_empty_per_epoch_cache()
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state.data.data, state.data.data.slot, 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(
        state.data.data, state.blck.root, bc0[0], cache)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, bc0[1], cache)

    pool[].addAttestation(attestation0)
    pool[].addAttestation(attestation1)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations may overlap, bigger first" & preset():
    var cache = get_empty_per_epoch_cache()

    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state.data.data, state.data.data.slot, 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(
        state.data.data, state.blck.root, bc0[0], cache)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, bc0[1], cache)

    attestation0.combine(attestation1, {})

    pool[].addAttestation(attestation0)
    pool[].addAttestation(attestation1)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations may overlap, smaller first" & preset():
    var cache = get_empty_per_epoch_cache()
    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(state.data.data,
        state.data.data.slot, 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(
        state.data.data, state.blck.root, bc0[0], cache)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, bc0[1], cache)

    attestation0.combine(attestation1, {})

    pool[].addAttestation(attestation1)
    pool[].addAttestation(attestation0)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Fork choice returns latest block with no attestations":
    var cache = get_empty_per_epoch_cache()
    let
      b1 = addTestBlock(state.data, blockPool[].tail.root, cache)
      b1Root = hash_tree_root(b1.message)
      b1Add = blockpool[].addRawBlock(b1Root, b1)[]

    pool[].addForkChoice_v2(b1Add)
    let head = pool[].selectHead()

    check:
      head == b1Add

    let
      b2 = addTestBlock(state.data, b1Root, cache)
      b2Root = hash_tree_root(b2.message)
      b2Add = blockpool[].addRawBlock(b2Root, b2)[]

    pool[].addForkChoice_v2(b2Add)
    let head2 = pool[].selectHead()

    check:
      head2 == b2Add

  timedTest "Fork choice returns block with attestation":
    var cache = get_empty_per_epoch_cache()
    let
      b10 = makeTestBlock(state.data, blockPool[].tail.root, cache)
      b10Root = hash_tree_root(b10.message)
      b10Add = blockpool[].addRawBlock(b10Root, b10)[]

    pool[].addForkChoice_v2(b10Add)
    let head = pool[].selectHead()

    check:
      head == b10Add

    let
      b11 = makeTestBlock(state.data, blockPool[].tail.root, cache,
        graffiti = Eth2Digest(data: [1'u8, 0, 0, 0 ,0 ,0 ,0 ,0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
      )
      b11Root = hash_tree_root(b11.message)
      b11Add = blockpool[].addRawBlock(b11Root, b11)[]

      bc1 = get_beacon_committee(
        state.data.data, state.data.data.slot, 1.CommitteeIndex, cache)
      attestation0 = makeAttestation(state.data.data, b10Root, bc1[0], cache)

    pool[].addForkChoice_v2(b11Add)
    pool[].addAttestation(attestation0)

    let head2 = pool[].selectHead()

    check:
      # Single vote for b10 and no votes for b11
      head2 == b10Add

    let
      attestation1 = makeAttestation(state.data.data, b11Root, bc1[1], cache)
      attestation2 = makeAttestation(state.data.data, b11Root, bc1[2], cache)
    pool[].addAttestation(attestation1)

    let head3 = pool[].selectHead()
    # Warning - the tiebreak are incorrect and guaranteed consensus fork, it should be bigger
    let smaller = if b10Root.data < b11Root.data: b10Add else: b11Add

    check:
      # Ties broken lexicographically in spec -> ?
      # all implementations favor the biggest root
      # TODO
      # currently using smaller as we have used for over a year
      head3 == smaller

    pool[].addAttestation(attestation2)

    let head4 = pool[].selectHead()

    check:
      # Two votes for b11
      head4 == b11Add

  timedTest "Trying to add a block twice tags the second as an error":
    var cache = get_empty_per_epoch_cache()
    let
      b10 = makeTestBlock(state.data, blockPool[].tail.root, cache)
      b10Root = hash_tree_root(b10.message)
      b10Add = blockpool[].addRawBlock(b10Root, b10)[]

    pool[].addForkChoice_v2(b10Add)
    let head = pool[].selectHead()

    check:
      head == b10Add

    # -------------------------------------------------------------
    # Add back the old block to ensure we have a duplicate error
    let b10_clone = b10 # Assumes deep copy
    let b10Add_clone = blockpool[].addRawBlock(b10Root, b10_clone)
    doAssert: b10Add_clone.error == Duplicate

  wrappedTimedTest "Trying to add a duplicate block from an old pruned epoch is tagged as an error":
    var cache = get_empty_per_epoch_cache()

    blockpool[].addFlags {skipBLSValidation}
    pool.forkChoice_v2.proto_array.prune_threshold = 1

    let
      b10 = makeTestBlock(state.data, blockPool[].tail.root, cache)
      b10Root = hash_tree_root(b10.message)
      b10Add = blockpool[].addRawBlock(b10Root, b10)[]

    pool[].addForkChoice_v2(b10Add)
    let head = pool[].selectHead()

    doAssert: head == b10Add

    let block_ok = state_transition(state.data, b10, {}, noRollback)
    doAssert: block_ok

    # -------------------------------------------------------------
    let b10_clone = b10 # Assumes deep copy

    # -------------------------------------------------------------
    # Pass an epoch
    var block_root = b10Root

    var attestations: seq[Attestation]

    for epoch in 0 ..< 5:
      let start_slot = compute_start_slot_at_epoch(Epoch epoch)
      for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:

        let new_block = makeTestBlock(state.data, block_root, cache, attestations = attestations)
        let block_ok = state_transition(state.data, new_block, {skipBLSValidation}, noRollback)
        doAssert: block_ok

        block_root = hash_tree_root(new_block.message)
        let blockRef = blockpool[].addRawBlock(block_root, new_block)[]

        pool[].addForkChoice_v2(blockRef)

        let head = pool[].selectHead()
        doassert: head == blockRef
        blockPool[].updateHead(head)

        attestations.setlen(0)
        for index in 0 ..< get_committee_count_at_slot(state.data.data, slot.Slot):
          let committee = get_beacon_committee(
              state.data.data, state.data.data.slot, index.CommitteeIndex, cache)

          # Create a bitfield filled with the given count per attestation,
          # exactly on the right-most part of the committee field.
          var aggregation_bits = init(CommitteeValidatorsBits, committee.len)
          for v in 0 ..< committee.len * 2 div 3 + 1:
            aggregation_bits[v] = true

          attestations.add Attestation(
            aggregation_bits: aggregation_bits,
            data: makeAttestationData(
              state.data.data, state.data.data.slot,
              index, blockroot
            )
            # signature: ValidatorSig()
          )

      cache = get_empty_per_epoch_cache()

    # -------------------------------------------------------------
    # Prune

    echo "\nPruning all blocks before: ", shortlog(blockPool[].finalizedHead), '\n'
    doAssert: blockPool[].finalizedHead.slot != 0

    pool[].pruneBefore(blockPool[].finalizedHead)
    doAssert: b10Root notin pool.forkChoice_v2

    # Add back the old block to ensure we have a duplicate error
    let b10Add_clone = blockpool[].addRawBlock(b10Root, b10_clone)
    doAssert: b10Add_clone.error == Duplicate
