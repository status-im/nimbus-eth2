# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/datatypes/gloas,
  ../beacon_chain/spec/[digest, presets],
  ../beacon_chain/consensus_object_pools/[
    execution_payload_pool, blockchain_dag],
  ../beacon_chain/beacon_clock,
  "."/[testutil, testdbutil]

func makeBid(
    slot: Slot,
    builderIndex: uint64,
    parentBlockRoot: Eth2Digest,
    parentBlockHash: Eth2Digest,
    value: Gwei): gloas.SignedExecutionPayloadBid =
  gloas.SignedExecutionPayloadBid(
    message: gloas.ExecutionPayloadBid(
      slot: slot,
      builder_index: builderIndex,
      parent_block_root: parentBlockRoot,
      parent_block_hash: parentBlockHash,
      block_hash: Eth2Digest(),
      fee_recipient: default(ExecutionAddress),
      gas_limit: 30000000,
      value: value,
      blob_kzg_commitments: default(KzgCommitments)),
    signature: default(ValidatorSig))

suite "Execution Payload Bid Pool":
  setup:
    let
      cfg = defaultRuntimeConfig
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = ChainDAGRef.init(
        cfg, cfg.makeTestDB(SLOTS_PER_EPOCH * 3), validatorMonitor, {})
      wallTime = BeaconTime(ns_since_genesis: 0)
      blockRoot = Eth2Digest.fromHex(
        "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
      parentHash1 = Eth2Digest.fromHex(
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
      parentHash2 = Eth2Digest.fromHex(
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    var pool = ExecutionPayloadBidPool.init(dag)

  test "Empty pool returns none":
    check:
      not pool.getHighestBidForSlotAndParent(
        1.Slot, blockRoot, PayloadAvailability.Timely).isSome()
      not pool.hasSeenBidFromBuilder(1.Slot, 0)

  test "Add and retrieve highest bid":
    let bid = makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei)

    pool.addBid(bid, PayloadAvailability.Timely, wallTime)

    let highest = pool.getHighestBidForSlotAndParent(
      10.Slot, blockRoot, PayloadAvailability.Timely)
    check:
      highest.isSome()
      highest.get().message.value == 100.Gwei
      highest.get().message.builder_index == 1

  test "Duplicate detection - same builder same slot":
    let
      bid1 = makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei)
      bid2 = makeBid(10.Slot, 1, blockRoot, parentHash1, 200.Gwei)

    pool.addBid(bid1, PayloadAvailability.Timely, wallTime)
    check pool.hasSeenBidFromBuilder(10.Slot, 1)

    pool.addBid(bid2, PayloadAvailability.Timely, wallTime)

    let highest = pool.getHighestBidForSlotAndParent(
      10.Slot, blockRoot, PayloadAvailability.Timely)
    check:
      highest.isSome()
      highest.get().message.value == 100.Gwei

  test "Highest bid selection - different builders":
    pool.addBid(
      makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(10.Slot, 2, blockRoot, parentHash1, 200.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(10.Slot, 3, blockRoot, parentHash1, 150.Gwei),
      PayloadAvailability.Timely, wallTime)

    let highest = pool.getHighestBidForSlotAndParent(
      10.Slot, blockRoot, PayloadAvailability.Timely)
    check:
      highest.isSome()
      highest.get().message.value == 200.Gwei
      highest.get().message.builder_index == 2

  test "Pruning removes old bids":
    let
      oldRoot = Eth2Digest.fromHex(
        "0x1111111111111111111111111111111111111111111111111111111111111111")
      newRoot = Eth2Digest.fromHex(
        "0x2222222222222222222222222222222222222222222222222222222222222222")

    pool.addBid(
      makeBid(10.Slot, 1, oldRoot, parentHash1, 100.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(100.Slot, 2, newRoot, parentHash1, 200.Gwei),
      PayloadAvailability.Timely, wallTime)

    check:
      10.Slot in pool.slotBids
      100.Slot in pool.slotBids

    pool.prune(50.Slot)

    check:
      10.Slot notin pool.slotBids
      100.Slot in pool.slotBids

  test "Track seen bids":
    pool.addBid(
      makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(10.Slot, 2, blockRoot, parentHash1, 200.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(10.Slot, 3, blockRoot, parentHash1, 50.Gwei),
      PayloadAvailability.Timely, wallTime)

    check:
      pool.hasSeenBidFromBuilder(10.Slot, 1)
      pool.hasSeenBidFromBuilder(10.Slot, 2)
      pool.hasSeenBidFromBuilder(10.Slot, 3)

    check pool.slotBids.len == 1

  test "Multiple bids for different beacon parent roots same slot":
    let
      blockRoot1 = blockRoot
      blockRoot2 = Eth2Digest.fromHex(
        "0x3333333333333333333333333333333333333333333333333333333333333333")
    pool.addBid(
      makeBid(10.Slot, 1, blockRoot1, parentHash1, 100.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(10.Slot, 2, blockRoot2, parentHash1, 150.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(10.Slot, 3, blockRoot1, parentHash1, 120.Gwei),
      PayloadAvailability.Timely, wallTime)

    let
      highest1 = pool.getHighestBidForSlotAndParent(
        10.Slot, blockRoot1, PayloadAvailability.Timely)
      highest2 = pool.getHighestBidForSlotAndParent(
        10.Slot, blockRoot2, PayloadAvailability.Timely)

    check:
      highest1.isSome()
      highest1.get().message.value == 120.Gwei
      highest1.get().message.builder_index == 3

      highest2.isSome()
      highest2.get().message.value == 150.Gwei
      highest2.get().message.builder_index == 2

    check pool.slotBids[10.Slot].highestBids.len == 2

  test "Multiple bids for different execution parent hashes same slot":
    pool.addBid(
      makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei),
      PayloadAvailability.Timely, wallTime)
    pool.addBid(
      makeBid(10.Slot, 2, blockRoot, parentHash2, 200.Gwei),
      PayloadAvailability.Withheld, wallTime)

    let
      bidTimely = pool.getHighestBidForSlotAndParent(
        10.Slot, blockRoot, PayloadAvailability.Timely)
      bidWithheld = pool.getHighestBidForSlotAndParent(
        10.Slot, blockRoot, PayloadAvailability.Withheld)

    check:
      bidTimely.isSome()
      bidTimely.get().message.value == 100.Gwei
      bidTimely.get().message.builder_index == 1

      bidWithheld.isSome()
      bidWithheld.get().message.value == 200.Gwei
      bidWithheld.get().message.builder_index == 2

    check pool.slotBids[10.Slot].highestBids.len == 2
