# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ../interpreter

proc setup_no_votes(): tuple[fork_choice: ForkChoice, ops: seq[Operation]] =
  let balances = newSeq[Gwei](16)
  let GenesisRoot = fakeHash(0)

  # Initialize the fork choice context
  result.fork_choice = initForkChoice(
    finalized_block_slot = Slot(0),
    finalized_block_state_root = default(Eth2Digest),
    justified_epoch = Epoch(1),
    finalized_epoch = Epoch(1),
    finalized_root = GenesisRoot
  ).get()

  # ----------------------------------

  # Head should be genesis
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(1),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: GenesisRoot
  )

  # Add block 2
  #
  #         0
  #        /
  #       2
  result.ops.add Operation(
    kind: ProcessBlock,
    slot: Slot(0),
    root: fakeHash(2),
    parent_root: GenesisRoot,
    blk_justified_epoch: Epoch(1),
    blk_finalized_epoch: Epoch(1)
  )

  # Head should be 2
  #
  #         0
  #        /
  #       2 <- head
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(1),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(2)
  )

  # Add block 1 as a fork
  #
  #         0
  #        / \
  #       2  1
  result.ops.add Operation(
    kind: ProcessBlock,
    slot: Slot(0),
    root: fakeHash(1),
    parent_root: GenesisRoot,
    blk_justified_epoch: Epoch(1),
    blk_finalized_epoch: Epoch(1)
  )

  # Head is still 2 due to tiebreaker as fakeHash(2) (0xD8...) > fakeHash(1) (0x7C...)
  #
  #          0
  #         / \
  # head-> 2  1
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(1),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(2)
  )

  # Add block 3
  #
  #         0
  #        / \
  #       2  1
  #          |
  #          3
  result.ops.add Operation(
    kind: ProcessBlock,
    slot: Slot(0),
    root: fakeHash(3),
    parent_root: fakeHash(1),
    blk_justified_epoch: Epoch(1),
    blk_finalized_epoch: Epoch(1)
  )

  # Head is still 2
  #
  #          0
  #         / \
  # head-> 2  1
  #           |
  #           3
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(1),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(2)
  )

  # Add block 4
  #
  #         0
  #        / \
  #       2  1
  #       |  |
  #       4  3
  result.ops.add Operation(
    kind: ProcessBlock,
    slot: Slot(0),
    root: fakeHash(4),
    parent_root: fakeHash(2),
    blk_justified_epoch: Epoch(1),
    blk_finalized_epoch: Epoch(1)
  )

  # Check that head is 4
  #
  #          0
  #         / \
  #        2  1
  #        |  |
  # head-> 4  3
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(1),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(4)
  )

  # Add block 5 with justified epoch of 2
  #
  #         0
  #        / \
  #       2  1
  #       |  |
  #       4  3
  #       |
  #       5 <- justified epoch = 2
  result.ops.add Operation(
    kind: ProcessBlock,
    slot: Slot(0),
    root: fakeHash(5),
    parent_root: fakeHash(4),
    blk_justified_epoch: Epoch(2),
    blk_finalized_epoch: Epoch(1)
  )

  # Ensure the head is still 4 whilst the justified epoch is 0.
  #
  #          0
  #         / \
  #        2  1
  #        |  |
  # head-> 4  3
  #        |
  #        5
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(1),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(4)
  )

  # Ensure that there is an error when starting from a block with the wrong justified epoch
  #      0
  #     / \
  #    2  1
  #    |  |
  #    4  3
  #    |
  #    5 <- starting from 5 with justified epoch 1 should error.
  result.ops.add Operation(
    kind: InvalidFindHead,
    justified_epoch: Epoch(1), # <--- Wrong epoch
    justified_root: fakeHash(5),
    finalized_epoch: Epoch(1),
    justified_state_balances: balances
  )

  # Set the justified epoch to 2 and the start block to 5 and ensure 5 is the head.
  #      0
  #     / \
  #    2  1
  #    |  |
  #    4  3
  #    |
  #    5 <- head + justified
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(2),
    justified_root: fakeHash(5),
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(5)
  )

  # Add block 6
  #
  #      0
  #     / \
  #     2  1
  #     |  |
  #     4  3
  #     |
  #     5 <- justified root
  #     |
  #     6
  result.ops.add Operation(
    kind: ProcessBlock,
    slot: Slot(0),
    root: fakeHash(6),
    parent_root: fakeHash(5),
    blk_justified_epoch: Epoch(2),
    blk_finalized_epoch: Epoch(1)
  )

  # Ensure 6 is the head
  #      0
  #     / \
  #    2  1
  #    |  |
  #    4  3
  #    |
  #    5 <- justified root
  #    |
  #    6 <- head
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(2),
    justified_root: fakeHash(5),
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(6)
  )

proc test_no_votes() =
  echo "  fork_choice - testing no votes"
  # for i in 0 ..< 6:
  #   echo "    block (", i, ") hash: ", fakeHash(i)
  # echo "    ------------------------------------------------------"

  var (ctx, ops) = setup_no_votes()
  ctx.run(ops)

test_no_votes()
