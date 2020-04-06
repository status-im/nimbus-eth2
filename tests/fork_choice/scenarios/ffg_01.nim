# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ../interpreter

proc setup_finality_01(): tuple[fork_choice: ForkChoice, ops: seq[Operation]] =
  var balances = @[Gwei(1), Gwei(1)]
  let GenesisRoot = fakeHash(0)

  # Initialize the fork choice context
  result.fork_choice = initForkChoice(
    finalized_block_slot = Slot(0),                   # Metadata unused in fork choice
    finalized_block_state_root = default(Eth2Digest), # Metadata unused in fork choice
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
    root: fakeHash(1),
    parent_root: GenesisRoot,
    blk_justified_epoch: Epoch(0),
    blk_finalized_epoch: Epoch(0)
  )
  result.ops.add Operation(
    kind: ProcessBlock,
    root: fakeHash(2),
    parent_root: fakeHash(1),
    blk_justified_epoch: Epoch(1),
    blk_finalized_epoch: Epoch(0)
  )
  result.ops.add Operation(
    kind: ProcessBlock,
    root: fakeHash(3),
    parent_root: fakeHash(2),
    blk_justified_epoch: Epoch(2),
    blk_finalized_epoch: Epoch(1)
  )

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
    justified_epoch: Epoch(0),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(0),
    justified_state_balances: balances,
    expected_head: fakeHash(3)
  )

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
    justified_epoch: Epoch(1),
    justified_root: fakeHash(2),
    finalized_epoch: Epoch(0),
    justified_state_balances: balances,
    expected_head: fakeHash(2)
  )

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
    justified_epoch: Epoch(2),
    justified_root: fakeHash(3),
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(3)
  )

proc test_ffg01() =
  echo "  fork_choice - testing finality #01"
  # for i in 0 ..< 4:
  #   echo "    block (", i, ") hash: ", fakeHash(i)
  # echo "    ------------------------------------------------------"

  var (ctx, ops) = setup_finality_01()
  ctx.run(ops)

test_ffg01()
