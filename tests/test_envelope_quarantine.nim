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

suite "Envelope Quarantine":
  setup:
    var quarantine = EnvelopeQuarantine.init()
    # Block root for testing
    let root1 = Eth2Digest.fromHex(
      "0x6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0001")

  test "Add missing":
    check root1 notin quarantine.missing
    quarantine.addMissing(root1)
    check root1 in quarantine.missing
    check root1 in quarantine.checkMissing(32)

  test "Add orphan":
    check (root1, 1'u64) notin quarantine.orphans
    quarantine.addOrphan(Slot 0, SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        builder_index: 1'u64)))
    check (root1, 1'u64) in quarantine.orphans
    quarantine.delOrphan(gloas.SignedBeaconBlock(root: root1))
    check (root1, 1'u64) notin quarantine.orphans

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

    quarantine.addOrphan(Slot 0, envelope)
    check quarantine.popOrphan(signedBlck) == Opt.some(envelope)
    check (root1, 1'u64) notin quarantine.orphans

    quarantine.addOrphan(Slot 0, envelope)
    check quarantine.popOrphan(gloas.SignedBeaconBlock(root: root1)) ==
      Opt.none(SignedExecutionPayloadEnvelope)
    check (root1, 1'u64) in quarantine.orphans

    quarantine.addOrphan(Slot 0, envelope)
    check quarantine.popOrphan(gloas.SignedBeaconBlock(message: blck)) ==
      Opt.none(SignedExecutionPayloadEnvelope)
    check (root1, 1'u64) in quarantine.orphans

  test "Has orphan":
    let envelope = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        builder_index: 2'u64))

    check not quarantine.hasOrphan(root1)
    quarantine.addOrphan(Slot 0, envelope)
    check quarantine.hasOrphan(root1)
    quarantine.delOrphan(gloas.SignedBeaconBlock(root: root1))
    check not quarantine.hasOrphan(root1)

  test "Add unviable":
    let envelope = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        builder_index: 1'u64))

    quarantine.addOrphan(Slot 0, envelope)
    quarantine.addMissing(root1)
    check:
      (root1, 1'u64) in quarantine.orphans
      root1 in quarantine.missing
      root1 notin quarantine.unviable

    quarantine.addUnviable(root1)
    check:
      (root1, 1'u64) notin quarantine.orphans
      root1 notin quarantine.missing
      root1 in quarantine.unviable

  test "Clean up orphans":
    let
      root2 = Eth2Digest.fromHex(
        "0x6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0002")
      root3 = Eth2Digest.fromHex(
        "0x6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0003")
      root4 = Eth2Digest.fromHex(
        "0x6aaaaaaaaa5aaaaaaaaa4aaaaaaaaa3aaaaaaaaa2aaaaaaaaa1aaaaaaaaa0004")

    quarantine.addOrphan(Slot 0, SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        payload: gloas.ExecutionPayload(slot_number: Slot(3))
      )
    ))
    quarantine.addOrphan(Slot 0, SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root2,
        payload: gloas.ExecutionPayload(slot_number: Slot(5))
      )
    ))
    quarantine.addOrphan(Slot 0, SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root3,
        payload: gloas.ExecutionPayload(slot_number: Slot(7))
      )
    ))

    check:
      (root1, 0'u64) in quarantine.orphans
      (root2, 0'u64) in quarantine.orphans
      (root3, 0'u64) in quarantine.orphans

    quarantine.addOrphan(Slot 3, SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root4,
        payload: gloas.ExecutionPayload(slot_number: Slot(9))
      )
    ))
    check:
      (root1, 0'u64) notin quarantine.orphans
      (root2, 0'u64) in quarantine.orphans
      (root3, 0'u64) in quarantine.orphans
      (root4, 0'u64) in quarantine.orphans

    quarantine.addOrphan(Slot 8, SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root4,
        payload: gloas.ExecutionPayload(slot_number: Slot(9))
      )
    ))
    check:
      (root2, 0'u64) notin quarantine.orphans
      (root3, 0'u64) notin quarantine.orphans
      (root4, 0'u64) in quarantine.orphans
