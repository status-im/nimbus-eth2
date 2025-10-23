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

# Helper to create a bid with minimal boilerplate
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

  test "Add and retrieve bid by slot and builder":
    let bid = makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei)

    check not pool.getBidForSlotAndBuilder(10.Slot, 1).isSome()

    pool.addBid(bid, wallTime)

    check:
      pool.getBidForSlotAndBuilder(10.Slot, 1).isSome()
      pool.getBidForSlotAndBuilder(10.Slot, 1).get().message.value == 100.Gwei

  test "Highest bid selection":
    pool.addBid(makeBid(10.Slot, 1, blockRoot, parentHash1, 100.Gwei), wallTime)
    pool.addBid(makeBid(10.Slot, 2, blockRoot, parentHash1, 200.Gwei), wallTime)

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
    pool.addBid(makeBid(106.Slot, 2, newRoot, parentHash1, 200.Gwei), wallTime)

    check:
      pool.hasBid(oldRoot)
      pool.hasBid(newRoot)

    pool.prune(74.Slot)

    check:
      not pool.hasBid(oldRoot)
      pool.hasBid(newRoot)
