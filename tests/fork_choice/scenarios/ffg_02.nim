# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# import ../interpreter # included to be able to use "suite"

func setup_finality_02(): tuple[fork_choice: ForkChoiceBackend, ops: seq[Operation]] =
  let balances = @[Gwei(1), Gwei(1)]
  let GenesisRoot = fakeHash(0)

  # Initialize the fork choice context
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

  # Build the following tree.
  #
  #                       0
  #                      / \
  #  just: 0, fin: 0 -> 1   2 <- just: 0, fin: 0
  #                     |   |
  #  just: 1, fin: 0 -> 3   4 <- just: 0, fin: 0
  #                     |   |
  #  just: 1, fin: 0 -> 5   6 <- just: 0, fin: 0
  #                     |   |
  #  just: 1, fin: 0 -> 7   8 <- just: 1, fin: 0
  #                     |   |
  #  just: 2, fin: 0 -> 9  10 <- just: 2, fin: 0

  #  Left branch
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Slot(1),
      root: fakeHash(1)),
    parent_root: GenesisRoot,
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot,
      root: fakeHash(3)),
    parent_root: fakeHash(1),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(1), epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot + 2,
      root: fakeHash(5)),
    parent_root: fakeHash(3),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(1), epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot + 4,
      root: fakeHash(7)),
    parent_root: fakeHash(5),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(1), epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(3).start_slot,
      root: fakeHash(9)),
    parent_root: fakeHash(7),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(3), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  # Build the following tree.
  #
  #                       0
  #                      / \
  #  just: 0, fin: 0 -> 1   2 <- just: 0, fin: 0
  #                     |   |
  #  just: 1, fin: 0 -> 3   4 <- just: 0, fin: 0
  #                     |   |
  #  just: 1, fin: 0 -> 5   6 <- just: 0, fin: 0
  #                     |   |
  #  just: 1, fin: 0 -> 7   8 <- just: 1, fin: 0
  #                     |   |
  #  just: 2, fin: 0 -> 9  10 <- just: 2, fin: 0

  #  Right branch
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Slot(2),
      root: fakeHash(2)),
    parent_root: GenesisRoot,
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(1).start_slot + 1,
      root: fakeHash(4)),
    parent_root: fakeHash(2),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot + 3,
      root: fakeHash(6)),
    parent_root: fakeHash(4),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(3).start_slot + 1,
      root: fakeHash(8)),
    parent_root: fakeHash(6),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(2), epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(5).start_slot + 1,
      root: fakeHash(10)),
    parent_root: fakeHash(8),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(4), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  # Ensure that if we start at 0 we find 10 (just: 0, fin: 0).
  #
  #           0  <-- start
  #          / \
  #         1   2
  #         |   |
  #         3   4
  #         |   |
  #         5   6
  #         |   |
  #         7   8
  #         |   |
  #         9  10 <-- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Same with justified_epoch 2
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(4), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Justified epoch 3 is invalid
  result.ops.add Operation(
    kind: InvalidFindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(4), epoch: Epoch(3)), # < Wrong epoch
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances)

  # Add a vote to 1.
  #
  #                 0
  #                / \
  #    +1 vote -> 1   2
  #               |   |
  #               3   4
  #               |   |
  #               5   6
  #               |   |
  #               7   8
  #               |   |
  #               9  10
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(0),
    block_root: fakeHash(1),
    target_epoch: Epoch(0))

  # Ensure that if we start at 0 we find 9 (just: 0, fin: 0).
  #
  #           0  <-- start
  #          / \
  #         1   2
  #         |   |
  #         3   4
  #         |   |
  #         5   6
  #         |   |
  #         7   8
  #         |   |
  # head -> 9  10
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Same with justified_epoch 2
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(3), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Justified epoch 3 is invalid
  result.ops.add Operation(
    kind: InvalidFindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(3)), # < Wrong epoch
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances)

  # Add a vote to 2.
  #
  #                 0
  #                / \
  #               1   2 <- +1 vote
  #               |   |
  #               3   4
  #               |   |
  #               5   6
  #               |   |
  #               7   8
  #               |   |
  #               9  10
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(1),
    block_root: fakeHash(2),
    target_epoch: Epoch(0))

  # Ensure that if we start at 0 we find 10 again (just: 0, fin: 0).
  #
  #           0  <-- start
  #          / \
  #         1   2
  #         |   |
  #         3   4
  #         |   |
  #         5   6
  #         |   |
  #         7   8
  #         |   |
  #         9  10 <-- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Same with justified_epoch 2
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(4), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Justified epoch 3 is invalid
  result.ops.add Operation(
    kind: InvalidFindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(3)), # < Wrong epoch
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances)

  # Ensure that if we start at 1 (instead of 0) we find 9 (just: 0, fin: 0).
  #
  #           0
  #          / \
  # start-> 1   2
  #         |   |
  #         3   4
  #         |   |
  #         5   6
  #         |   |
  #         7   8
  #         |   |
  # head -> 9  10
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      # Justified: In production the root/epoch mismatch isn't used.
      justified: Checkpoint(root: fakeHash(1), epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Same with justified_epoch 2
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(3), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(9))

  # Justified epoch 3 is invalid
  result.ops.add Operation(
    kind: InvalidFindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(5), epoch: Epoch(3)), # < Wrong epoch
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances)

  # Ensure that if we start at 2 (instead of 0) we find 10 (just: 0, fin: 0).
  #
  #           0
  #          / \
  #         1   2 <- start
  #         |   |
  #         3   4
  #         |   |
  #         5   6
  #         |   |
  #         7   8
  #         |   |
  #         9  10 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      # Justified: In production this can't happen
      justified: Checkpoint(root: fakeHash(2), epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Same with justified_epoch 2
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(4), epoch: Epoch(2)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(10))

  # Justified epoch 3 is invalid
  result.ops.add Operation(
    kind: InvalidFindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(4), epoch: Epoch(3)), # < Wrong epoch
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances)

proc test_ffg02() =
  test "fork_choice - testing finality #02":
    # for i in 0 ..< 12:
    #   echo "    block (", i, ") hash: ", fakeHash(i)
    # echo "    ------------------------------------------------------"

    var (ctx, ops) = setup_finality_02()
    ctx.run(ops)

test_ffg02()
