# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/consensus_object_pools/[
    block_quarantine, full_block_pool]

from stew/byteutils import hexToByteArray

suite "Full block pool":
  setup:
    var pool = FullBlockPool.init()
    let root1 = Eth2Digest(data:
        hexToByteArray[32]("6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0001".toOpenArray(0, 63)))

  test "Add envelope":
    let defaultEnvelope = SignedExecutionPayloadEnvelope()
    check pool.getEnvelope(defaultEnvelope).isNone()
    pool.addEnvelope(defaultEnvelope)
    check pool.getEnvelope(defaultEnvelope) == Opt.some(defaultEnvelope)

    let envelope = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        builder_index: 1'u64))
    check pool.getEnvelope(envelope).isNone()
    pool.addEnvelope(envelope)
    check pool.getEnvelope(envelope) == Opt.some(envelope)

    let noBuilderIdx = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(beacon_block_root: root1))
    check pool.getEnvelope(noBuilderIdx).isNone()

  test "Block has been seen":
    let defaultBlock = gloas.SignedBeaconBlock()
    check not pool.isBlockSeen(defaultBlock)
    pool.addBlock(defaultBlock)
    check pool.isBlockSeen(defaultBlock)

    let blck = gloas.SignedBeaconBlock(root: root1)
    check not pool.isBlockSeen(blck)
    pool.addBlock(blck)
    check pool.isBlockSeen(blck)

  test "Envelope status":
    let envelope = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1))
    pool.addEnvelope(envelope)
    check pool.isEnvelopeSeen(envelope)
    check not pool.isEnvelopeValid(envelope)
    pool.markEnvelopeValid(envelope)
    check pool.isEnvelopeSeen(envelope)
    check pool.isEnvelopeValid(envelope)

  test "Envelope progress":
    let envelope = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1))
    pool.addEnvelope(envelope)
    check pool.isEnvelopeSeen(envelope)
    check not pool.isEnvelopeProcessed(envelope)

    pool.markEnvelopeProcessed(envelope)
    check pool.isEnvelopeProcessed(envelope)
