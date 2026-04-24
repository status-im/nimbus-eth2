# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/consensus_object_pools/envelope_quarantine,
  ../beacon_chain/spec/forks

from stew/byteutils import hexToByteArray

suite "Envelope Quarantine":
  setup:
    var quarantine = EnvelopeQuarantine.init()
    # Block root for testing
    let root1 = Eth2Digest(data:hexToByteArray[32](
      "6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0001"
      .toOpenArray(0, 63)))

  test "Add missing":
    check root1 notin quarantine.missing
    quarantine.addMissing(root1)
    check root1 in quarantine.missing

  test "Add orphan":
    check root1 notin quarantine.orphans
    quarantine.addOrphan(SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        builder_index: 1'u64)))
    check root1 in quarantine.orphans
    check 1'u64 in quarantine.orphans[root1]
    quarantine.delOrphan(gloas.SignedBeaconBlock(root: root1))
    check root1 notin quarantine.orphans

  test "Pop orphan":
    let
      envelope = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(
          beacon_block_root: root1,
          builder_index: 1'u64))
      blckBid = gloas.SignedExecutionPayloadBid(
        message: gloas.ExecutionPayloadBid(
          builder_index: 1'u64))
      blck = gloas.BeaconBlock(
        body: gloas.BeaconBlockBody(
          signed_execution_payload_bid: blckBid))
      signedBlck = gloas.SignedBeaconBlock(root: root1, message: blck)

    quarantine.addOrphan(envelope)
    check quarantine.popOrphan(signedBlck) == Opt.some(envelope)
    check root1 in quarantine.orphans

    quarantine.addOrphan(envelope)
    check quarantine.popOrphan(gloas.SignedBeaconBlock(root: root1)) ==
      Opt.none(SignedExecutionPayloadEnvelope)
    check root1 in quarantine.orphans

    quarantine.addOrphan(envelope)
    check quarantine.popOrphan(gloas.SignedBeaconBlock(message: blck)) ==
      Opt.none(SignedExecutionPayloadEnvelope)
    check root1 in quarantine.orphans

  test "Clean up orphans":
    let
      root2 = Eth2Digest(data:hexToByteArray[32](
        "6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0002"
        .toOpenArray(0, 63)))
      root3 = Eth2Digest(data:hexToByteArray[32](
        "6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0003"
        .toOpenArray(0, 63)))

    quarantine.addOrphan(SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        payload: gloas.ExecutionPayload(slot_number: Slot(3))
      )
    ))
    quarantine.addOrphan(SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root2,
        payload: gloas.ExecutionPayload(slot_number: Slot(5))
      )
    ))
    quarantine.addOrphan(SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root3,
        payload: gloas.ExecutionPayload(slot_number: Slot(7))
      )
    ))

    quarantine.cleanupOrphans(Slot(3))
    check quarantine.orphans.len == 2
    quarantine.cleanupOrphans(Slot(8))
    check quarantine.orphans.len == 0
