# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# import ../interpreter # included to be able to use "suite"

func setup_finality_01(): tuple[fork_choice: ForkChoiceBackend, ops: seq[Operation]] =
  let balances = @[Gwei(1), Gwei(1)]
  let GenesisRoot = fakeHash(0)

  # Initialize the fork choice context
  result.fork_choice = ForkChoiceBackend.init(
    FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  # ----------------------------------

  # Head should be genesis
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: GenesisRoot)

  # Build the following chain
  #
  #   0 <- just: 0, fin: 0
  #   |
  #   1 <- just: 0, fin: 0
  #   |
  #   2 <- just: 1, fin: 0
  #   |
  #   3 <- just: 2, fin: 1
  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(1).start_slot,
      root: fakeHash(1)),
    parent_root: GenesisRoot,
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(2).start_slot,
      root: fakeHash(2)),
    parent_root: fakeHash(1),
    blk_checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(1), epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))))

  result.ops.add Operation(
    kind: ProcessBlock,
    bid: BlockId(
      slot: Epoch(3).start_slot,
      root: fakeHash(3)),
    parent_root: fakeHash(2),
    blk_Checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(2), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(1), epoch: Epoch(1))))

  # Ensure that with justified epoch 0 we find 3
  #
  #     0 <- start
  #     |
  #     1
  #     |
  #     2
  #     |
  #     3 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: GenesisRoot, epoch: Epoch(0)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(3))

  # Ensure that with justified epoch 1 we find 2
  #
  #     0
  #     |
  #     1
  #     |
  #     2 <- start
  #     |
  #     3 <- head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(1), epoch: Epoch(1)),
      finalized: Checkpoint(root: GenesisRoot, epoch: Epoch(0))),
    justified_state_balances: balances,
    expected_head: fakeHash(2))

  # Ensure that with justified epoch 2 we find 3
  #
  #     0
  #     |
  #     1
  #     |
  #     2
  #     |
  #     3 <- start + head
  result.ops.add Operation(
    kind: FindHead,
    checkpoints: FinalityCheckpoints(
      justified: Checkpoint(root: fakeHash(2), epoch: Epoch(2)),
      finalized: Checkpoint(root: fakeHash(1), epoch: Epoch(1))),
    justified_state_balances: balances,
    expected_head: fakeHash(3))

proc test_ffg01() =
  test "fork_choice - testing finality #01":
    # for i in 0 ..< 4:
    #   echo "    block (", i, ") hash: ", fakeHash(i)
    # echo "    ------------------------------------------------------"

    var (ctx, ops) = setup_finality_01()
    ctx.run(ops)

test_ffg01()
