# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# import ../interpreter # included to be able to use "suite"

func setup_votes(): tuple[fork_choice: ForkChoiceBackend, ops: seq[Operation]] =
  var balances = @[Gwei(1), Gwei(1)]
  let GenesisRoot = fakeHash(0)

  # Initialize the fork choice context
  # We start with epoch 0 fully finalized to avoid epoch 0 special cases.
  result.fork_choice = ForkChoiceBackend.init(
    FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  # ----------------------------------

  # Head should be genesis
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: GenesisRoot)

  # Add block 2
  #
  #         0
  #        /
  #       2
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(1).start_slot + 2,
      root: fakeHash(2)),
    parent_root: GenesisRoot,
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  # Head should be 2
  #
  #         0
  #        /
  #       2 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(2))

  # Add block 1 as a fork
  #
  #         0
  #        / \
  #       2  1
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(1).start_slot + 1,
      root: fakeHash(1)),
    parent_root: GenesisRoot,
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  # Head is still 2 due to tiebreaker as fakeHash(2) (0xD8...) > fakeHash(1) (0x7C...)
  #
  #          0
  #         / \
  # head-> 2  1
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(2))

  # Add a vote to block 1
  #
  #          0
  #         / \
  #        2  1 <- +vote
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(0),
    block_root: fakeHash(1),
    target_epoch: Epoch(2))

  # Head is now 1 as 1 has an extra vote
  #
  #          0
  #         / \
  #        2  1 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(1))

  # Add a vote to block 2
  #
  #           0
  #          / \
  # +vote-> 2   1
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(1),
    block_root: fakeHash(2),
    target_epoch: Epoch(2))

  # Head is back to 2 due to tiebreaker as fakeHash(2) (0xD8...) > fakeHash(1) (0x7C...)
  #
  #          0
  #         / \
  # head-> 2  1
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(2))

  # Add block 3 as on chain 1
  #
  #         0
  #        / \
  #       2  1
  #          |
  #          3
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(1).start_slot + 3,
      root: fakeHash(3)),
    parent_root: fakeHash(1),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  # Head is still 2
  #
  #          0
  #         / \
  # head-> 2  1
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(2)
  )

  # Move validator #0 vote from 1 to 3
  #
  #          0
  #         / \
  #        2   1 <- -vote
  #            |
  #            3 <- +vote
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(0),
    block_root: fakeHash(3),
    target_epoch: Epoch(3))

  # Head is still 2
  #
  #          0
  #         / \
  # head-> 2  1
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(2))

  # Move validator #1 vote from 2 to 1 (this is an equivocation, but fork choice doesn't
  # care)
  #
  #           0
  #          / \
  # -vote-> 2   1 <- +vote
  #             |
  #             3
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(1),
    block_root: fakeHash(1),
    target_epoch: Epoch(3))

  # Head is now 3
  #
  #          0
  #         / \
  #        2  1
  #           |
  #           3 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(3))

  # Add block 4 on chain 1-3
  #
  #         0
  #        / \
  #       2  1
  #          |
  #          3
  #          |
  #          4
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(1).start_slot + 4,
      root: fakeHash(4)),
    parent_root: fakeHash(3),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  # Head is now 4
  #
  #          0
  #         / \
  #        2  1
  #           |
  #           3
  #           |
  #           4 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(4))

  # Add block 5, which has a justified epoch of 2.
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           /
  #          5 <- justified epoch = 2
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot,
      root: fakeHash(5)),
    parent_root: fakeHash(4),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))))

  # Ensure that 5 is filtered out and the head stays at 4.
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4 <- head
  #           /
  #          5
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(4))

  # Add block 6, which has a justified epoch of 0.
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6 <- justified epoch = 0
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot + 1,
      root: fakeHash(6)),
    parent_root: fakeHash(4),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  # Move both votes to 5.
  #
  #           0
  #          / \
  #         2   1
  #             |
  #             3
  #             |
  #             4
  #            / \
  # +2 vote-> 5   6
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(0),
    block_root: fakeHash(5),
    target_epoch: Epoch(4))

  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(1),
    block_root: fakeHash(5),
    target_epoch: Epoch(4))

  # Add blocks 7, 8 and 9. Adding these blocks helps test the `best_descendant`
  # functionality.
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         /
  #        9
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot + 2,
      root: fakeHash(7)),
    parent_root: fakeHash(5),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot + 3,
      root: fakeHash(8)),
    parent_root: fakeHash(7),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))))

  # Finalizes 5
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot + 4,
      root: fakeHash(9)),
    parent_root: fakeHash(8),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))))

  # Ensure that 6 is the head, even though 5 has all the votes. This is testing to ensure
  # that 5 is filtered out due to a differing justified epoch.
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6 <- head
  #          |
  #          7
  #          |
  #          8
  #         /
  #         9
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(6))

  # Change fork-choice justified epoch to 1, and the start block to 5 and ensure that 9 is
  # the head.
  #
  # << Change justified epoch to 1 >>
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         /
  # head-> 9
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Update votes to block 9
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         /
  #        9 <- +2 votes
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(0),
    block_root: fakeHash(9),
    target_epoch: Epoch(5))

  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(1),
    block_root: fakeHash(9),
    target_epoch: Epoch(5))

  # Head should still be 9
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Add block 10 (also finalizes 5)
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         / \
  #        9  10
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(3).start_slot,
      root: fakeHash(10)),
    parent_root: fakeHash(8),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))))

  # Head should still be 9
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Introduce 2 new validators
  balances = @[Gwei(1), Gwei(1), Gwei(1), Gwei(1)]

  # Have them vote for block 10
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         / \
  #        9  10 <- +2 votes
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(2),
    block_root: fakeHash(10),
    target_epoch: Epoch(5))

  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(3),
    block_root: fakeHash(10),
    target_epoch: Epoch(5))

  # Check that the head is now 10.
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  #           / \
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         / \
  #        9  10 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Set the last 2 validators balances to 0
  balances = @[Gwei(1), Gwei(1), Gwei(0), Gwei(0)]

  # head should be 9 again
  #            .
  #           |
  #           8
  #          / \
  # head -> 9  10
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Set the last 2 validators balances back to 1
  balances = @[Gwei(1), Gwei(1), Gwei(1), Gwei(1)]

  # head should be 10 again
  #            .
  #           |
  #           8
  #          / \
  #         9  10 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Remove the validators
  balances = @[Gwei(1), Gwei(1)]

  # head should be 9 again
  #            .
  #           |
  #           8
  #          / \
  # head -> 9  10
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Ensure that pruning does prune.
  #
  #
  #          0
  #         / \
  #        2   1
  #            |
  #            3
  #            |
  #            4
  # -------pruned here ------
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         / \
  #        9  10
  # Note: 5 and 6 become orphans
  # - 5 is the new root
  # - 6 is a discarded chain
  result.ops.add Operation(
    kind: Prune,
    prune_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    expected_len: 6)

  # Prune shouldn't have changed the head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Add block 11
  #
  #          5   6
  #          |
  #          7
  #          |
  #          8
  #         / \
  #        9  10
  #        |
  #        11
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(3).start_slot + 1,
      root: fakeHash(11)),
    parent_root: fakeHash(9),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))))

  # Head is now 11
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(5), epoch: Epoch(2))),
    justified_state_balances: balances,
    expected_head: fakeHash(11))

proc test_votes() =
  test "fork_choice - testing with votes":
    # for i in 0 ..< 12:
    #   echo "    block (", i, ") hash: ", fakeHash(i)
    # echo "    ------------------------------------------------------"

    var (ctx, ops) = setup_votes()
    ctx.run(ops)

test_votes()
