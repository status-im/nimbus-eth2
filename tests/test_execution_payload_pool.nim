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
    value: Gwei): SignedExecutionPayloadBid =
  SignedExecutionPayloadBid(
    message: ExecutionPayloadBid(
      slot: slot,
      builder_index: builderIndex,
      parent_block_root: parentBlockRoot,
      parent_block_hash: parentBlockHash,
      block_hash: Eth2Digest(),
      fee_recipient: default(ExecutionAddress),
      gas_limit: 30000000,
      value: value,
      blob_kzg_commitments_root: Eth2Digest()),
    signature: default(ValidatorSig))

suite "Execution Payload Bid Pool":
  setup:
    let
      cfg = defaultRuntimeConfig
      validatorMonitor = newClone(ValidatorMonitor.init(cfg.timeParams))
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
      not pool.getHighestBidForSlotAndParent(1.Slot, parentHash1).isSome()
      not pool.hasBidForBlockRoot(blockRoot)
      not pool.getBidForBlockRoot(blockRoot).isSome()
      not pool.hasSeenBidFromBuilder(1.Slot, 0)

  test "Add and retrieve highest bid":
    let bid = makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei)

    pool.addBid(bid, wallTime)

    check:
      pool.getHighestBidForSlotAndParent(10.Slot, parentHash1).isSome()
      pool.getHighestBidForSlotAndParent(10.Slot, parentHash1).get().message.value == 100.Gwei
      pool.getHighestBidForSlotAndParent(10.Slot, parentHash1).get().message.builder_index == 1

  test "Duplicate detection - same builder same slot":
    let
      bid1 = makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei)
      bid2 = makeBid(10.Slot, 1, blockRoot, parentHash1, 200.Gwei)

    pool.addBid(bid1, wallTime)
    check pool.hasSeenBidFromBuilder(10.Slot, 1)

    pool.addBid(bid2, wallTime)

    let highest = pool.getHighestBidForSlotAndParent(10.Slot, parentHash1)
    check:
      highest.isSome()
      highest.get().message.value == 100.Gwei

  test "Highest bid selection - different builders":
    pool.addBid(makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei), wallTime)
    pool.addBid(makeBid(10.Slot, 2, blockRoot, parentHash1, 200.Gwei), wallTime)
    pool.addBid(makeBid(10.Slot, 3, blockRoot, parentHash1, 150.Gwei), wallTime)

    let highest = pool.getHighestBidForSlotAndParent(10.Slot, parentHash1)
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

    pool.addBid(makeBid(10.Slot, 1, oldRoot, parentHash1, 100.Gwei), wallTime)
    pool.addBid(makeBid(100.Slot, 2, newRoot, parentHash1, 200.Gwei), wallTime)

    check:
      pool.hasBidForBlockRoot(oldRoot)
      pool.hasBidForBlockRoot(newRoot)

    pool.prune(50.Slot)

    check:
      not pool.hasBidForBlockRoot(oldRoot)
      pool.hasBidForBlockRoot(newRoot)

  test "Track seen bids":
    pool.addBid(makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei), wallTime)
    pool.addBid(makeBid(10.Slot, 2, blockRoot, parentHash1, 200.Gwei), wallTime)
    pool.addBid(makeBid(10.Slot, 3, blockRoot, parentHash1, 50.Gwei), wallTime)

    check:
      pool.hasSeenBidFromBuilder(10.Slot, 1)
      pool.hasSeenBidFromBuilder(10.Slot, 2)
      pool.hasSeenBidFromBuilder(10.Slot, 3)

    check pool.slotBids.len == 1

  test "Multiple bids for different parents same slot":
    pool.addBid(makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei), wallTime)
    pool.addBid(makeBid(10.Slot, 2, blockRoot, parentHash2, 150.Gwei), wallTime)
    pool.addBid(makeBid(10.Slot, 3, blockRoot, parentHash1, 120.Gwei), wallTime)

    let
      highest1 = pool.getHighestBidForSlotAndParent(10.Slot, parentHash1)
      highest2 = pool.getHighestBidForSlotAndParent(10.Slot, parentHash2)

    check:
      highest1.isSome()
      highest1.get().message.value == 120.Gwei
      highest1.get().message.builder_index == 3

      highest2.isSome()
      highest2.get().message.value == 150.Gwei
      highest2.get().message.builder_index == 2

    check:
      pool.hasSeenBidFromBuilder(10.Slot, 1)
      pool.hasSeenBidFromBuilder(10.Slot, 2)
      pool.hasSeenBidFromBuilder(10.Slot, 3)

    check pool.slotBids.len == 1

    check pool.slotBids[10.Slot].highestBids.len == 2
