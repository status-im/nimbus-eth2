# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  chronicles,
  ../beacon_chain/spec/[beaconstate, helpers, state_transition],
  ../beacon_chain/spec/datatypes/[base, phase0, gloas],
  ../beacon_chain/consensus_object_pools/[blockchain_dag],
  ../beacon_chain/fork_choice/[fork_choice_types, fork_choice],
  ../beacon_chain/validators/validator_monitor,
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/gossip_processing/batch_validation,
  ./testutil, ./testdbutil

suite "Vote Processing - Slot Tracking":
  test "Gloas: Votes update based on slot":
    var backend = ForkChoiceBackend()
    backend.votes = newSeq[VoteTracker](10)

    var cfg = defaultRuntimeConfig
    cfg.GLOAS_FORK_EPOCH = Epoch(0)

    let
      validator_idx = ValidatorIndex(5)
      block_root1 = Eth2Digest.fromHex("0x4444444444444444444444444444444444444444444444444444444444444444")
    backend.process_attestation(
      validator_idx, block_root1, Epoch(3), Slot(100), false, cfg)

    check:
      backend.votes[5].next_slot == Slot(100)
      backend.votes[5].next_root == block_root1
      backend.votes[5].payload_present == false

    # Try to update with older slot - should NOT update
    let block_root2 = Eth2Digest.fromHex("0x5555555555555555555555555555555555555555555555555555555555555555")
    backend.process_attestation(
      validator_idx, block_root2, Epoch(3), Slot(99), true, cfg)

    check:
      backend.votes[5].next_slot == Slot(100)
      backend.votes[5].next_root == block_root1

    # Update with newer slot - should update
    let block_root3 = Eth2Digest.fromHex("0x6666666666666666666666666666666666666666666666666666666666666666")
    backend.process_attestation(
      validator_idx, block_root3, Epoch(3), Slot(101), true, cfg)

    check:
      backend.votes[5].next_slot == Slot(101)
      backend.votes[5].next_root == block_root3
      backend.votes[5].payload_present == true

  test "Gloas: payload_present flag tracks EMPTY vs FULL preference":
    # When attesting to a block from a previous slot, validators signal
    # whether they prefer building on EMPTY or FULL branch.
    var backend = ForkChoiceBackend()
    backend.votes = newSeq[VoteTracker](10)

    var cfg = defaultRuntimeConfig
    cfg.GLOAS_FORK_EPOCH = Epoch(0)

    let validator_idx = ValidatorIndex(3)

    # Vote preferring EMPTY branch (attestation.data.index = 0)
    backend.process_attestation(
      validator_idx,
      Eth2Digest.fromHex("0x7777777777777777777777777777777777777777777777777777777777777777"),
      Epoch(5), Slot(150), false, cfg)

    check:
      backend.votes[3].payload_present == false

    # Later vote preferring FULL branch (attestation.data.index = 1)
    backend.process_attestation(
      validator_idx,
      Eth2Digest.fromHex("0x8888888888888888888888888888888888888888888888888888888888888888"),
      Epoch(5), Slot(151), true, cfg)

    check:
      backend.votes[3].payload_present == true

  suite "PTC Voting - Payload Timeliness":
    test "is_payload_timely: False when payload not locally available":
      var backend = ForkChoiceBackend()
      let block_root = Eth2Digest.fromHex(
        "0x4444444444444444444444444444444444444444444444444444444444444444")

      backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
      for i in 0..<300:
        backend.ptc_vote[block_root][i] = true

      # Don't mark as locally available
      # (on_execution_payload was not called)
      check:
        not backend.is_payload_timely(block_root)

    test "is_payload_timely: False with exactly 256 votes (boundary)":
      var backend = ForkChoiceBackend()
      let block_root = Eth2Digest.fromHex(
        "0x7777777777777777777777777777777777777777777777777777777777777777")

      # Exactly 256 votes (at threshold, not above)
      backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
      for i in 0..<256:
        backend.ptc_vote[block_root][i] = true

      backend.execution_payload_states[block_root] = Eth2Digest.fromHex(
        "0x8888888888888888888888888888888888888888888888888888888888888888")

      check:
        not backend.is_payload_timely(block_root)

    test "is_payload_timely: True with 257 votes (just above threshold)":
      var backend = ForkChoiceBackend()
      let block_root = Eth2Digest.fromHex(
        "0x9999999999999999999999999999999999999999999999999999999999999999")

      # 257 votes (just above threshold)
      backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
      for i in 0..<257:
        backend.ptc_vote[block_root][i] = true

      backend.execution_payload_states[block_root] = Eth2Digest.fromHex(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
      check:
        backend.is_payload_timely(block_root)

    test "is_payload_timely: Both conditions must be met":
      var backend = ForkChoiceBackend()

      # Case 1: Votes YES, Local NO → FALSE
      let root1 = Eth2Digest.fromHex(
        "0x1111111111111111111111111111111111111111111111111111111111111111")
      backend.ptc_vote[root1] = newSeq[bool](PTC_SIZE)
      for i in 0..<300:
        backend.ptc_vote[root1][i] = true
      # Don't add to execution_payload_states
      check:
        not backend.is_payload_timely(root1)

      # Case 2: Votes NO, Local YES → FALSE
      let root2 = Eth2Digest.fromHex(
        "0x2222222222222222222222222222222222222222222222222222222222222222")
      backend.ptc_vote[root2] = newSeq[bool](PTC_SIZE)
      for i in 0..<100:
        backend.ptc_vote[root2][i] = true
      backend.execution_payload_states[root2] = Eth2Digest.fromHex(
        "0x3333333333333333333333333333333333333333333333333333333333333333")
      check:
        not backend.is_payload_timely(root2)

      # Case 3: Votes YES, Local YES → TRUE
      let root3 = Eth2Digest.fromHex(
        "0x4444444444444444444444444444444444444444444444444444444444444444")
      backend.ptc_vote[root3] = newSeq[bool](PTC_SIZE)
      for i in 0..<300:
        backend.ptc_vote[root3][i] = true
      backend.execution_payload_states[root3] = Eth2Digest.fromHex(
        "0x5555555555555555555555555555555555555555555555555555555555555555")
      check:
        backend.is_payload_timely(root3)

suite "Gloas Payload Extension":
  setup:
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = Epoch(0)
    cfg.BELLATRIX_FORK_EPOCH = Epoch(0)
    cfg.CAPELLA_FORK_EPOCH = Epoch(0)
    cfg.DENEB_FORK_EPOCH = Epoch(0)
    cfg.ELECTRA_FORK_EPOCH = Epoch(0)
    cfg.FULU_FORK_EPOCH = Epoch(0)
    cfg.GLOAS_FORK_EPOCH = Epoch(0)

    var
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = ChainDAGRef.init(
        cfg, cfg.makeTestDB(SLOTS_PER_EPOCH * 3), validatorMonitor, {})
      forkChoice = newClone(ForkChoice.init(
        dag.getFinalizedEpochRef(), dag.finalizedHead.blck))

  test "should_extend_payload: True when payload is timely":
    let block_root = Eth2Digest.fromHex(
      "0x1111111111111111111111111111111111111111111111111111111111111111")

    # Set up PTC votes
    forkChoice[].backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
    for i in 0..<300:
      forkChoice[].backend.ptc_vote[block_root][i] = true

    # Mark payload as locally available
    forkChoice[].backend.execution_payload_states[block_root] = Eth2Digest.fromHex(
      "0x2222222222222222222222222222222222222222222222222222222222222222")

    check:
      forkChoice[].should_extend_payload(block_root)

  test "should_extend_payload: True when no proposer boost":
    let block_root = Eth2Digest.fromHex(
      "0x3333333333333333333333333333333333333333333333333333333333333333")

    # Payload not timely
    forkChoice[].backend.ptc_vote[block_root] = newSeq[bool](PTC_SIZE)
    for i in 0..<100:
      forkChoice[].backend.ptc_vote[block_root][i] = true

    # No proposer boost
    forkChoice[].checkpoints.proposer_boost_root = ZERO_HASH

    check:
      forkChoice[].should_extend_payload(block_root)

  test "should_extend_payload: True when proposer boost on different chain":
    let
      genesis_root = dag.genesis.get().root
      blockB_root = Eth2Digest.fromHex(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
      blockC_root = Eth2Digest.fromHex(
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")

    # Add blocks to proto_array
    discard forkChoice[].backend.process_block(
      BlockId(root: blockB_root, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: blockC_root, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # Payload for B NOT timely
    forkChoice[].backend.ptc_vote[blockB_root] = newSeq[bool](PTC_SIZE)
    for i in 0..<100:
      forkChoice[].backend.ptc_vote[blockB_root][i] = true

    # Block C gets proposer boost (different chain)
    forkChoice[].checkpoints.proposer_boost_root = blockC_root

    check:
      forkChoice[].should_extend_payload(blockB_root)

  test "should_extend_payload: False when proposer boost on same chain":
    let
      genesis_root = dag.genesis.get().root
      blockB_root = Eth2Digest.fromHex(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
      blockD_root = Eth2Digest.fromHex(
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")

    # Add blocks to proto_array
    discard forkChoice[].backend.process_block(
      BlockId(root: blockB_root, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: blockD_root, slot: Slot(2)), # Builds on B
      blockB_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # Payload for B not timely
    forkChoice[].backend.ptc_vote[blockB_root] = newSeq[bool](PTC_SIZE)
    for i in 0..<100:
      forkChoice[].backend.ptc_vote[blockB_root][i] = true

    # Block D gets proposer boost (on same chain as B)
    forkChoice[].checkpoints.proposer_boost_root = blockD_root

    check:
      not forkChoice[].should_extend_payload(blockB_root)

suite "Vote Support Logic - When Votes Support Nodes":
  setup:
    var cfg = defaultRuntimeConfig
    cfg.ALTAIR_FORK_EPOCH = Epoch(0)
    cfg.BELLATRIX_FORK_EPOCH = Epoch(0)
    cfg.CAPELLA_FORK_EPOCH = Epoch(0)
    cfg.DENEB_FORK_EPOCH = Epoch(0)
    cfg.ELECTRA_FORK_EPOCH = Epoch(0)
    cfg.FULU_FORK_EPOCH = Epoch(0)
    cfg.GLOAS_FORK_EPOCH = Epoch(0)

    var
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = ChainDAGRef.init(
        cfg, cfg.makeTestDB(SLOTS_PER_EPOCH * 3), validatorMonitor, {})
      forkChoice = newClone(ForkChoice.init(
        dag.getFinalizedEpochRef(), dag.finalizedHead.blck))

  test "Pre-Gloas: Simple root matching":
    # Before Gloas, voting is simple: vote.root == node.root

    dag.cfg.GLOAS_FORK_EPOCH = Epoch(1000) # Disable Gloas
    
    let 
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x1111111111111111111111111111111111111111111111111111111111111111")

    # Add block to proto_array
    discard forkChoice[].backend.process_block(
      BlockId(root: block_root, slot: Slot(50)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    let 
      node = ForkChoiceNode(
        root: block_root,
        payloadStatus: PAYLOAD_STATUS_PENDING)
      vote = VoteTracker(
        next_root: block_root,
        next_slot: Slot(50),
        next_epoch: Epoch(0),
        payload_present: false)

    check:
      forkChoice[].is_supporting_vote(node, vote, dag)
  
  test "Rule 1: PENDING status always gets support":
    # PENDING is the parent of EMPTY/FULL virtual nodes
    # Any vote for the block supports PENDING
  
    let 
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x2222222222222222222222222222222222222222222222222222222222222222")

    # Add block to proto_array
    discard forkChoice[].backend.process_block(
      BlockId(root: block_root, slot: Slot(100)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    let pending_node = ForkChoiceNode(
      root: block_root,
      payloadStatus: PAYLOAD_STATUS_PENDING)

    # Vote from same slot with payload_present = false
    let vote1 = VoteTracker(
      next_root: block_root,
      next_slot: Slot(100),
      next_epoch: Epoch(0),
      payload_present: false)

    # Vote from later slot with payload_present = true
    let vote2 = VoteTracker(
      next_root: block_root,
      next_slot: Slot(101),
      next_epoch: Epoch(0),
      payload_present: true)

    # Both support PENDING
    check:
      forkChoice[].is_supporting_vote(pending_node, vote1, dag)
      forkChoice[].is_supporting_vote(pending_node, vote2, dag)

  test "Rule 2: Same-slot vote doesn't support EMPTY/FULL":
    # When attesting to block at same slot, you're voting for
    # the BLOCK (PENDING), not choosing EMPTY vs FULL

    let 
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x3333333333333333333333333333333333333333333333333333333333333333")
      block_slot = Slot(100)

    # Add block to proto_array at slot 100
    discard forkChoice[].backend.process_block(
      BlockId(root: block_root, slot: block_slot),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    let 
      empty_node = ForkChoiceNode(
        root: block_root,
        payloadStatus: PAYLOAD_STATUS_EMPTY)
      full_node = ForkChoiceNode(
        root: block_root,
        payloadStatus: PAYLOAD_STATUS_FULL)

    let same_slot_vote = VoteTracker(
      next_root: block_root,
      next_slot: block_slot,
      next_epoch: Epoch(0),
      payload_present: false)
    
    # Same-slot vote should NOT support EMPTY or FULL
    check:
      not forkChoice[].is_supporting_vote(empty_node, same_slot_vote, dag)
      not forkChoice[].is_supporting_vote(full_node, same_slot_vote, dag)

  test "Rule 3: Next-slot vote with payload_present=false supports EMPTY":
    # At slot N+1, attesting to slot N block with index=0
    # preferring EMPTY branch

    let 
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x4444444444444444444444444444444444444444444444444444444444444444")
      block_slot = Slot(100)

    discard forkChoice[].backend.process_block(
      BlockId(root: block_root, slot: block_slot),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    let 
      empty_node = ForkChoiceNode(
        root: block_root,
        payloadStatus: PAYLOAD_STATUS_EMPTY)
      full_node = ForkChoiceNode(
        root: block_root,
        payloadStatus: PAYLOAD_STATUS_FULL)

    # Vote from NEXT slot preferring EMPTY
    let empty_vote = VoteTracker(
      next_root: block_root,
      next_slot: Slot(101),
      next_epoch: Epoch(0),
      payload_present: false)

    check:
      forkChoice[].is_supporting_vote(empty_node, empty_vote, dag)
      not forkChoice[].is_supporting_vote(full_node, empty_vote, dag)

  test "Rule 3: Next-slot vote with payload_present=true supports FULL":
    # At slot N+1, attesting to slot N block with index=1
    # preferring full branch"

    let 
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x5555555555555555555555555555555555555555555555555555555555555555")
      block_slot = Slot(100)

    # Add block to proto_array
    discard forkChoice[].backend.process_block(
      BlockId(root: block_root, slot: block_slot),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    let 
      empty_node = ForkChoiceNode(
        root: block_root,
        payloadStatus: PAYLOAD_STATUS_EMPTY)
      full_node = ForkChoiceNode(
        root: block_root,
        payloadStatus: PAYLOAD_STATUS_FULL)

    # Vote from NEXT slot preferring FULL
    let full_vote = VoteTracker(
      next_root: block_root,
      next_slot: Slot(101),
      next_epoch: Epoch(0),
      payload_present: true)

    check:
      not forkChoice[].is_supporting_vote(empty_node, full_vote, dag)
      forkChoice[].is_supporting_vote(full_node, full_vote, dag)

  test "Vote timing is critical for EMPTY vs FULL distinction":
    # The SAME validator voting at different times has different meaning

    let 
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x6666666666666666666666666666666666666666666666666666666666666666")
      block_slot = Slot(100)

    # Add block to proto_array
    discard forkChoice[].backend.process_block(
      BlockId(root: block_root, slot: block_slot),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    let empty_node = ForkChoiceNode(
      root: block_root,
      payloadStatus: PAYLOAD_STATUS_EMPTY)

    # Vote from slot 100 (SAME as block)
    let same_slot_vote = VoteTracker(
      next_root: block_root,
      next_slot: Slot(100),  # Explicit: same as block_slot
      next_epoch: Epoch(0),
      payload_present: false)

    # Vote from slot 101 (NEXT after block)
    let next_slot_vote = VoteTracker(
      next_root: block_root,
      next_slot: Slot(101),
      next_epoch: Epoch(0),
      payload_present: false)

    # Same slot doesn't support EMPTY (neutral, supports PENDING only)
    check:
      not forkChoice[].is_supporting_vote(empty_node, same_slot_vote, dag)
    
    # Next slot supports EMPTY (actual preference)
    check:
      forkChoice[].is_supporting_vote(empty_node, next_slot_vote, dag)
    
    # Vote from slot 99 (BEFORE block) - shouldn't happen
    let before_slot_vote = VoteTracker(
      next_root: block_root,
      next_slot: Slot(99),
      next_epoch: Epoch(0),
      payload_present: false)

    # Before or same slot: doesn't support EMPTY
    check:
      not forkChoice[].is_supporting_vote(empty_node, before_slot_vote, dag)

  test "Rule 4: Vote for descendant can support ancestor":
    # If vote is for child block C that builds on parent B,
    # the vote can support B (with matching payload status)

    let 
      genesis_root = dag.genesis.get().root
      parent_root = Eth2Digest.fromHex(
        "0x7777777777777777777777777777777777777777777777777777777777777777")
      child_root = Eth2Digest.fromHex(
        "0x8888888888888888888888888888888888888888888888888888888888888888")

    # Setup proto_array: Parent (slot 100) ← Child (slot 101)
    discard forkChoice[].backend.process_block(
      BlockId(root: parent_root, slot: Slot(100)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: child_root, slot: Slot(101)),
      parent_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    let 
      parent_node = ForkChoiceNode(
        root: parent_root,
        payloadStatus: PAYLOAD_STATUS_PENDING)
      child_vote = VoteTracker(
        next_root: child_root,
        next_slot: Slot(101),
        next_epoch: Epoch(0),
        payload_present: false)

    # Vote for child should support parent (PENDING accepts all)
    check:
      forkChoice[].is_supporting_vote(parent_node, child_vote, dag)
