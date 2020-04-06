# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ../interpreter

proc setup_votes(): tuple[fork_choice: ForkChoice, ops: seq[Operation]] =
  let balances = @[Gwei(1), Gwei(1)]
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
  # result.ops.add Operation(
  #   kind: FindHead,
  #   justified_epoch: Epoch(1),
  #   justified_root: GenesisRoot,
  #   finalized_epoch: Epoch(1),
  #   justified_state_balances: balances,
  #   expected_head: GenesisRoot
  # )

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
  # result.ops.add Operation(
  #   kind: FindHead,
  #   justified_epoch: Epoch(1),
  #   justified_root: GenesisRoot,
  #   finalized_epoch: Epoch(1),
  #   justified_state_balances: balances,
  #   expected_head: fakeHash(2)
  # )

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

  # Add a vote to block 1
  #
  #          0
  #         / \
  #        2  1 <- +vote
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(0),
    block_root: fakeHash(1),
    target_epoch: Epoch(2)
  )

  # Head is now 1 as 1 has an extra vote
  #
  #          0
  #         / \
  #        2  1 <- head
  result.ops.add Operation(
    kind: FindHead,
    justified_epoch: Epoch(1),
    justified_root: GenesisRoot,
    finalized_epoch: Epoch(1),
    justified_state_balances: balances,
    expected_head: fakeHash(1)
  )

  # Add a vote to block 2
  #
  #           0
  #          / \
  # +vote-> 2   1
  result.ops.add Operation(
    kind: ProcessAttestation,
    validator_index: ValidatorIndex(1),
    block_root: fakeHash(2),
    target_epoch: Epoch(2)
  )

  # Head is back to 2 due to tiebreaker as fakeHash(2) (0xD8...) > fakeHash(1) (0x7C...)
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

proc test_votes() =
  echo "  fork_choice - testing with votes"
  for i in 0 ..< 11:
    echo "    block (", i, ") hash: ", fakeHash(i)
  echo "    ------------------------------------------------------"

  var (ctx, ops) = setup_votes()
  ctx.run(ops)

test_votes()
