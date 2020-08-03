# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest,
  chronicles,
  stew/byteutils,
  ./testutil, ./testblockutil, ../research/simutils,
  ../beacon_chain/spec/[crypto, datatypes, digest, validator, state_transition,
                        helpers, beaconstate, presets],
  ../beacon_chain/[beacon_node_types, attestation_pool, extras],
  ../beacon_chain/fork_choice/[fork_choice_types, fork_choice],
  ../beacon_chain/block_pools/[chain_dag, clearance]

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
      chainDag = newClone(init(ChainDAGRef, defaultRuntimePreset, makeTestDB(SLOTS_PER_EPOCH * 3)))
      quarantine = newClone(QuarantineRef())
      pool = newClone(AttestationPool.init(chainDag, quarantine))
      state = newClone(loadTailState(chainDag))
    # Slot 0 is a finalized slot - won't be making attestations for it..
    check:
      process_slots(state.data, state.data.data.slot + 1)

  timedTest "Can add and retrieve simple attestation" & preset():
    var cache = StateCache()
    let
      # Create an attestation for slot 1!
      beacon_committee = get_beacon_committee(
        state.data.data, state.data.data.slot, 0.CommitteeIndex, cache)
      attestation = makeAttestation(
        state.data.data, state.blck.root, beacon_committee[0], cache)

    pool[].addAttestation(attestation, attestation.data.slot)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations may arrive in any order" & preset():
    var cache = StateCache()
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
    pool[].addAttestation(attestation1, attestation1.data.slot)
    pool[].addAttestation(attestation0, attestation1.data.slot)

    discard process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations should be combined" & preset():
    var cache = StateCache()
    let
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state.data.data, state.data.data.slot, 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(
        state.data.data, state.blck.root, bc0[0], cache)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, bc0[1], cache)

    pool[].addAttestation(attestation0, attestation0.data.slot)
    pool[].addAttestation(attestation1, attestation1.data.slot)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations may overlap, bigger first" & preset():
    var cache = StateCache()

    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(
        state.data.data, state.data.data.slot, 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(
        state.data.data, state.blck.root, bc0[0], cache)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, bc0[1], cache)

    attestation0.combine(attestation1, {})

    pool[].addAttestation(attestation0, attestation0.data.slot)
    pool[].addAttestation(attestation1, attestation1.data.slot)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Attestations may overlap, smaller first" & preset():
    var cache = StateCache()
    var
      # Create an attestation for slot 1!
      bc0 = get_beacon_committee(state.data.data,
        state.data.data.slot, 0.CommitteeIndex, cache)
      attestation0 = makeAttestation(
        state.data.data, state.blck.root, bc0[0], cache)
      attestation1 = makeAttestation(
        state.data.data, state.blck.root, bc0[1], cache)

    attestation0.combine(attestation1, {})

    pool[].addAttestation(attestation1, attestation1.data.slot)
    pool[].addAttestation(attestation0, attestation0.data.slot)

    check:
      process_slots(state.data, MIN_ATTESTATION_INCLUSION_DELAY.Slot + 1)

    let attestations = pool[].getAttestationsForBlock(state.data.data)

    check:
      attestations.len == 1

  timedTest "Fork choice returns latest block with no attestations":
    var cache = StateCache()
    let
      b1 = addTestBlock(state.data, chainDag.tail.root, cache)
      b1Add = chainDag.addRawBlock(quarantine, b1) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

    let head = pool[].selectHead(b1Add[].slot)

    check:
      head == b1Add[]

    let
      b2 = addTestBlock(state.data, b1.root, cache)
      b2Add = chainDag.addRawBlock(quarantine, b2) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

    let head2 = pool[].selectHead(b2Add[].slot)

    check:
      head2 == b2Add[]

  timedTest "Fork choice returns block with attestation":
    var cache = StateCache()
    let
      b10 = makeTestBlock(state.data, chainDag.tail.root, cache)
      b10Add = chainDag.addRawBlock(quarantine, b10) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

    let head = pool[].selectHead(b10Add[].slot)

    check:
      head == b10Add[]

    let
      b11 = makeTestBlock(state.data, chainDag.tail.root, cache,
        graffiti = GraffitiBytes [1'u8, 0, 0, 0 ,0 ,0 ,0 ,0 ,0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      )
      b11Add = chainDag.addRawBlock(quarantine, b11) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

      bc1 = get_beacon_committee(
        state.data.data, state.data.data.slot, 1.CommitteeIndex, cache)
      attestation0 = makeAttestation(state.data.data, b10.root, bc1[0], cache)

    pool[].addAttestation(attestation0, attestation0.data.slot)

    let head2 = pool[].selectHead(b10Add[].slot)

    check:
      # Single vote for b10 and no votes for b11
      head2 == b10Add[]

    let
      attestation1 = makeAttestation(state.data.data, b11.root, bc1[1], cache)
      attestation2 = makeAttestation(state.data.data, b11.root, bc1[2], cache)
    pool[].addAttestation(attestation1, attestation1.data.slot)

    let head3 = pool[].selectHead(b10Add[].slot)
    let bigger = if b11.root.data < b10.root.data: b10Add else: b11Add

    check:
      # Ties broken lexicographically in spec -> ?
      head3 == bigger[]

    pool[].addAttestation(attestation2, attestation2.data.slot)

    let head4 = pool[].selectHead(b11Add[].slot)

    check:
      # Two votes for b11
      head4 == b11Add[]

  timedTest "Trying to add a block twice tags the second as an error":
    var cache = StateCache()
    let
      b10 = makeTestBlock(state.data, chainDag.tail.root, cache)
      b10Add = chainDag.addRawBlock(quarantine, b10) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

    let head = pool[].selectHead(b10Add[].slot)

    check:
      head == b10Add[]

    # -------------------------------------------------------------
    # Add back the old block to ensure we have a duplicate error
    let b10_clone = b10 # Assumes deep copy
    let b10Add_clone = chainDag.addRawBlock(quarantine, b10_clone) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

    doAssert: b10Add_clone.error == Duplicate

  wrappedTimedTest "Trying to add a duplicate block from an old pruned epoch is tagged as an error":
    chainDag.updateFlags.incl {skipBLSValidation}
    pool.forkChoice.backend.proto_array.prune_threshold = 1
    var cache = StateCache()
    let
      b10 = makeTestBlock(state.data, chainDag.tail.root, cache)
      b10Add = chainDag.addRawBlock(quarantine, b10) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

    let head = pool[].selectHead(b10Add[].slot)

    doAssert: head == b10Add[]

    let block_ok = state_transition(defaultRuntimePreset, state.data, b10, {}, noRollback)
    doAssert: block_ok

    # -------------------------------------------------------------
    let b10_clone = b10 # Assumes deep copy

    # -------------------------------------------------------------
    # Pass an epoch
    var block_root = b10.root

    var attestations: seq[Attestation]

    for epoch in 0 ..< 5:
      let start_slot = compute_start_slot_at_epoch(Epoch epoch)
      let committees_per_slot =
        get_committee_count_per_slot(state.data.data, Epoch epoch, cache)
      for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
        let new_block = makeTestBlock(
          state.data, block_root, cache, attestations = attestations)
        let block_ok = state_transition(
          defaultRuntimePreset, state.data, new_block, {skipBLSValidation}, noRollback)
        doAssert: block_ok

        block_root = new_block.root
        let blockRef = chainDag.addRawBlock(quarantine, new_block) do (
            blckRef: BlockRef, signedBlock: SignedBeaconBlock,
            state: HashedBeaconState):
          # Callback add to fork choice if valid
          let epochRef = getEpochInfo(blckRef, state.data)
          pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

        let head = pool[].selectHead(blockRef[].slot)
        doassert: head == blockRef[]
        chainDag.updateHead(head)

        attestations.setlen(0)
        for index in 0'u64 ..< committees_per_slot:
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

      cache = StateCache()

    # -------------------------------------------------------------
    # Prune

    doAssert: chainDag.finalizedHead.slot != 0

    pool[].prune()
    doAssert: b10.root notin pool.forkChoice.backend

    # Add back the old block to ensure we have a duplicate error
    let b10Add_clone = chainDag.addRawBlock(quarantine, b10_clone) do (
          blckRef: BlockRef, signedBlock: SignedBeaconBlock,
          state: HashedBeaconState):
        # Callback add to fork choice if valid
        let epochRef = getEpochInfo(blckRef, state.data)
        pool[].addForkChoice(epochRef, blckRef, signedBlock.message, blckRef.slot)

    doAssert: b10Add_clone.error == Duplicate
