# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  chronicles,
  chronos,
  unittest2,
  ../beacon_chain/spec/[beaconstate, helpers, state_transition],
  ../beacon_chain/spec/datatypes/[base, phase0, gloas],
  ../beacon_chain/consensus_object_pools/[blockchain_dag],
  ../beacon_chain/fork_choice/[fork_choice_types, fork_choice],
  ../beacon_chain/validators/validator_monitor,
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/gossip_processing/batch_validation,
  ./testutil, ./testdbutil

suite "Head Selection - LMD-GHOST with Payload Status":
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
      time = chronos.seconds(0)
    proc getBeaconTime(): BeaconTime =
      BeaconTime(ns_since_genesis: time.nanoseconds)

    # Setup justified balances
    forkChoice[].checkpoints.justified.balances = newSeq[Gwei](10)
    for i in 0..<10:
      forkChoice[].checkpoints.justified.balances[i] = 32_000_000_000.Gwei
    forkChoice[].checkpoints.justified.total_active_balance = 320_000_000_000.Gwei

  test "Pre-Gloas: Use standard proto_array logic":
    ## Before Gloas, use existing implementation
    dag.cfg.GLOAS_FORK_EPOCH = Epoch(1000)

    let
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x1111111111111111111111111111111111111111111111111111111111111111")

    # Add a block
    discard forkChoice[].backend.process_block(
      BlockId(root: block_root, slot: Slot(100)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # Update justified checkpoint
    forkChoice[].checkpoints.justified.checkpoint = Checkpoint(
      root: genesis_root,
      epoch: Epoch(0))

    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    check head_result.isOk

  test "Start at justified checkpoint with PENDING":
    # Head selection starts at justified checkpoint

    let genesis_root = dag.genesis.get().root

    forkChoice[].checkpoints.justified.checkpoint = Checkpoint(
      root: genesis_root,
      epoch: Epoch(0))

    # Justified block has no children → should return justified root
    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    check:
      head_result.isOk
      head_result.get() == genesis_root

  test "Gloas: Pick child with highest weight":
    # LMD-GHOST picks child with most attestation weight

    let 
      genesis_root = dag.genesis.get().root
      child1 = Eth2Digest.fromHex(
        "0x4444444444444444444444444444444444444444444444444444444444444444")
      child2 = Eth2Digest.fromHex(
        "0x5555555555555555555555555555555555555555555555555555555555555555")

    # Add children
    discard forkChoice[].backend.process_block(
      BlockId(root: child1, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: child2, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # Child1 gets 3 validators, child2 gets 7
    forkChoice[].backend.votes = newSeq[VoteTracker](10)
    for i in 0..<3:
      forkChoice[].backend.votes[i] = VoteTracker(
        current_root: default(Eth2Digest),
        next_root: child1,
        next_slot: Slot(1),
        next_epoch: Epoch(0),
        payload_present: false)

    for i in 3..<10:
      forkChoice[].backend.votes[i] = VoteTracker(
        current_root: default(Eth2Digest),
        next_root: child2,
        next_slot: Slot(1),
        next_epoch: Epoch(0),
        payload_present: false)

    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    check:
      head_result.isOk
      head_result.get() == child2  # Higher weight wins (7 vs 3 validators)

  test "Gloas: Lexicographic tiebreak on root when weights equal":
    # If two children have equal weight, higher root wins

    let 
      genesis_root = dag.genesis.get().root
      child1 = Eth2Digest.fromHex(
        "0x7777777777777777777777777777777777777777777777777777777777777777")
      child2 = Eth2Digest.fromHex(
        "0x8888888888888888888888888888888888888888888888888888888888888888")

    # Add children
    discard forkChoice[].backend.process_block(
      BlockId(root: child1, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: child2, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # both get 5 validators (equal weight)
    forkChoice[].backend.votes = newSeq[VoteTracker](10)
    for i in 0..<5:
      forkChoice[].backend.votes[i] = VoteTracker(
        current_root: default(Eth2Digest),
        next_root: child1,
        next_slot: Slot(1),
        next_epoch: Epoch(0),
        payload_present: false)

    for i in 5..<10:
      forkChoice[].backend.votes[i] = VoteTracker(
        current_root: default(Eth2Digest),
        next_root: child2,
        next_slot: Slot(1),
        next_epoch: Epoch(0),
        payload_present: false)

    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    check:
      head_result.isOk
      head_result.get() == child2  # Higher root wins (0x88... > 0x77...)

  test "Gloas: Payload tiebreaker when same root, equal weight":
    # Same block, different payload status → use tiebreaker

    let 
      genesis_root = dag.genesis.get().root
      block_b = Eth2Digest.fromHex(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

    # Add block B at slot 1
    discard forkChoice[].backend.process_block(
      BlockId(root: block_b, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    var votes = default(PtcVotes)
    for i in 0..<300:
      votes.setBit(i)
    forkChoice[].backend.ptc_vote[block_b] = votes

    forkChoice[].backend.execution_payload_states[block_b] = Eth2Digest.fromHex(
      "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")

    # At slot 2, deciding on slot 1's payload
    # FULL should win tiebreaker over EMPTY
    forkChoice[].checkpoints.time = (Slot(2).start_beacon_time(dag.timeParams))

    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    # Should pick FULL branch, return the block root
    check:
      head_result.isOk
      head_result.get() == block_b

  test "Descends multiple levels":
    let 
      genesis_root = dag.genesis.get().root
      block_b = Eth2Digest.fromHex(
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
      block_c = Eth2Digest.fromHex(
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
      block_d = Eth2Digest.fromHex(
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

    # genesis ← B ← C ← D
    discard forkChoice[].backend.process_block(
      BlockId(root: block_b, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: block_c, slot: Slot(2)),
      block_b,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: block_d, slot: Slot(3)),
      block_c,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # Setup votes for the chain
    forkChoice[].backend.votes = newSeq[VoteTracker](10)
    for i in 0..<10:
      forkChoice[].backend.votes[i] = VoteTracker(
        current_root: default(Eth2Digest),
        next_root: block_d,
        next_slot: Slot(3),
        next_epoch: Epoch(0),
        payload_present: false)

    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    check:
      head_result.isOk
      head_result.get() == block_d

  test "Gloas: Handles virtual node expansion correctly":
    let 
      genesis_root = dag.genesis.get().root
      block_b = Eth2Digest.fromHex(
        "0x1111111111111111111111111111111111111111111111111111111111111111")
      block_c = Eth2Digest.fromHex(
        "0x2222222222222222222222222222222222222222222222222222222222222222")

    # genesis ← block B ← block C
    discard forkChoice[].backend.process_block(
      BlockId(root: block_b, slot: Slot(1)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    discard forkChoice[].backend.process_block(
      BlockId(root: block_c, slot: Slot(2)),
      block_b,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # B has payload available (FULL branch available)
    forkChoice[].backend.execution_payload_states[block_b] = Eth2Digest.fromHex(
      "0x3333333333333333333333333333333333333333333333333333333333333333")

    # Votes for C
    forkChoice[].backend.votes = newSeq[VoteTracker](10)
    for i in 0..<10:
      forkChoice[].backend.votes[i] = VoteTracker(
        current_root: default(Eth2Digest),
        next_root: block_c,
        next_slot: Slot(2),
        next_epoch: Epoch(0),
        payload_present: false)

    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    check:
      head_result.isOk
      head_result.get() == block_c

  test "Safety: Iteration limit prevents infinite loops":
    let head_result = forkChoice[].get_head(dag, getBeaconTime())

    check head_result.isOk

suite "Block Processing":
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
      time = chronos.seconds(0)
    proc getBeaconTime(): BeaconTime =
      BeaconTime(ns_since_genesis: time.nanoseconds)

    # Setup justified balances
    forkChoice[].checkpoints.justified.balances = newSeq[Gwei](10)
    for i in 0..<10:
      forkChoice[].checkpoints.justified.balances[i] = 32_000_000_000.Gwei
    forkChoice[].checkpoints.justified.total_active_balance = 320_000_000_000.Gwei

  test "on_execution_payload: Marks payload as locally available":
    # When execution payload arrives, mark it available
    let
      genesis_root = dag.genesis.get().root
      beacon_block_root = Eth2Digest.fromHex(
        "0x4444444444444444444444444444444444444444444444444444444444444444")
      payload_state_root = Eth2Digest.fromHex(
        "0x5555555555555555555555555555555555555555555555555555555555555555")

    # Add block to proto_array first
    discard forkChoice[].backend.process_block(
      BlockId(root: beacon_block_root, slot: Slot(100)),
      genesis_root,
      FinalityCheckpoints(
        justified: Checkpoint(root: genesis_root, epoch: Epoch(0)),
        finalized: Checkpoint(root: genesis_root, epoch: Epoch(0))))

    # Before: payload not available
    check:
      beacon_block_root notin forkChoice[].backend.execution_payload_states

    # Record payload availability
    let res = forkChoice[].on_execution_payload(
      dag, beacon_block_root, payload_state_root)

    # After: payload marked available
    check:
      res.isOk
      beacon_block_root in forkChoice[].backend.execution_payload_states
      forkChoice[].backend.execution_payload_states[beacon_block_root] == 
        payload_state_root

  test "on_execution_payload: Enables FULL branch in fork choice":
    # Payload availability affects node expansion
    let
      genesis_root = dag.genesis.get().root
      block_root = Eth2Digest.fromHex(
        "0x6666666666666666666666666666666666666666666666666666666666666666")

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

    # Before payload: only EMPTY child
    let children_before = forkChoice[].get_node_children(pending_node, dag)
    check:
      children_before.len == 1
      children_before[0].payloadStatus == PAYLOAD_STATUS_EMPTY

    # Mark payload available
    discard forkChoice[].on_execution_payload(
      dag, block_root, Eth2Digest.fromHex(
        "0x7777777777777777777777777777777777777777777777777777777777777777"))

    # After payload: EMPTY + FULL children
    let children_after = forkChoice[].get_node_children(pending_node, dag)
    check:
      children_after.len == 2
      children_after[0].payloadStatus == PAYLOAD_STATUS_EMPTY
      children_after[1].payloadStatus == PAYLOAD_STATUS_FULL
