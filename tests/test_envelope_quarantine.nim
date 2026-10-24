# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/strutils,
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
    check FetchRecord(root: root1) in quarantine.checkMissing(32)

  test "Add orphan":
    let envelope = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        builder_index: 1'u64))
    check not quarantine.hasOrphan(envelope)
    quarantine.addOrphan(Slot 0, envelope)
    check:
      quarantine.hasOrphan(root1)
      quarantine.hasOrphan(envelope)
    quarantine.remove(root1)

    quarantine.addUntrustedOrphan(Slot 0, envelope)
    check:
      quarantine.hasOrphan(root1)
      quarantine.hasOrphan(envelope)
    quarantine.remove(root1)

    check:
      not quarantine.hasOrphan(root1)
      not quarantine.hasOrphan(envelope)

  test "Pop orphan":
    debugHezeComment "Heze has different SignedExecutionPayloadBid"
    let
      envelope = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(
          beacon_block_root: root1,
          builder_index: 1'u64,
          payload: gloas.ExecutionPayload(slot_number: Slot(1)))
      )
      blckBid = gloas.SignedExecutionPayloadBid(
        message: gloas.ExecutionPayloadBid(
          builder_index: 1'u64))
      blck = gloas.BeaconBlock(
        body: gloas.BeaconBlockBody(
          signed_execution_payload_bid: blckBid))
      signedBlck = gloas.SignedBeaconBlock(root: root1, message: blck)

    quarantine.addUntrustedOrphan(Slot 0, envelope)
    check:
      quarantine.popOrphan(signedBlck) ==
        Opt.none(SignedExecutionPayloadEnvelope)
      quarantine.popUntrustedOrphans(signedBlck) == @[envelope]
      not quarantine.hasOrphan(envelope)

    quarantine.addOrphan(Slot 0, envelope)
    quarantine.addUntrustedOrphan(Slot 0, envelope)
    check:
      quarantine.popOrphan(signedBlck) == Opt.some(envelope)
      quarantine.popUntrustedOrphans(signedBlck) ==
        default(seq[SignedExecutionPayloadEnvelope])
      not quarantine.hasOrphan(envelope)

    quarantine.addUntrustedOrphan(Slot 0, envelope)
    quarantine.addUntrustedOrphan(Slot 0, envelope)
    check:
      quarantine.popOrphan(signedBlck) ==
        Opt.none(SignedExecutionPayloadEnvelope)
      quarantine.popUntrustedOrphans(signedBlck) == @[envelope]
      not quarantine.hasOrphan(envelope)

    quarantine.addUntrustedOrphan(Slot 0, envelope)
    quarantine.addOrphan(Slot 0, envelope)
    quarantine.addUntrustedOrphan(Slot 0, SignedExecutionPayloadEnvelope(
      message: envelope.message,
      signature: ValidatorSig.fromHex(
        "0x" & "00".repeat(95) & "0a").expect("envelope signature")
    ))
    check:
      quarantine.popUntrustedOrphans(signedBlck) ==
        default(seq[SignedExecutionPayloadEnvelope])
      quarantine.popOrphan(signedBlck) == Opt.some(envelope)
      not quarantine.hasOrphan(envelope)

    quarantine.addOrphan(Slot 0, envelope)
    check:
      quarantine.popOrphan(gloas.SignedBeaconBlock(message: blck)) ==
        Opt.none(SignedExecutionPayloadEnvelope)
      quarantine.hasOrphan(envelope)

  test "Has orphan":
    let
      envelope1 = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(
          beacon_block_root: root1,
          builder_index: 2'u64,
          payload: gloas.ExecutionPayload(slot_number: Slot(1)))
      )
      envelope2 = SignedExecutionPayloadEnvelope(
        message: envelope1.message,
        signature: ValidatorSig.fromHex(
          "0x" & "00".repeat(95) & "0a").expect("envelope signature")
      )

    check:
      not quarantine.hasOrphan(root1)
      not quarantine.hasOrphan(envelope1)

    quarantine.addOrphan(Slot 0, envelope1)
    check:
      quarantine.hasOrphan(root1)
      quarantine.hasOrphan(envelope1)

    quarantine.remove(root1)
    check:
      not quarantine.hasOrphan(root1)
      not quarantine.hasOrphan(envelope1)

    quarantine.addUntrustedOrphan(Slot(0), envelope1)
    quarantine.addUntrustedOrphan(Slot(0), envelope2)
    check:
      quarantine.hasOrphan(envelope1)
      quarantine.hasOrphan(envelope2)

  test "Add unviable":
    let envelope = SignedExecutionPayloadEnvelope(
      message: ExecutionPayloadEnvelope(
        beacon_block_root: root1,
        builder_index: 1'u64))

    quarantine.addOrphan(Slot 0, envelope)
    quarantine.addMissing(root1)
    check:
      quarantine.hasOrphan(envelope)
      root1 in quarantine.missing
      root1 notin quarantine.unviable

    quarantine.addUnviable(root1)
    check:
      not quarantine.hasOrphan(envelope)
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

      envelope1 = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(
          beacon_block_root: root1,
          payload: gloas.ExecutionPayload(slot_number: Slot(3))
        )
      )
      envelope2 = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(
          beacon_block_root: root2,
          payload: gloas.ExecutionPayload(slot_number: Slot(5))
        )
      )
      envelope3 = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(
          beacon_block_root: root3,
          payload: gloas.ExecutionPayload(slot_number: Slot(7))
        )
      )
      envelope4 = SignedExecutionPayloadEnvelope(
        message: ExecutionPayloadEnvelope(
          beacon_block_root: root4,
          payload: gloas.ExecutionPayload(slot_number: Slot(9))
        )
      )

    quarantine.addOrphan(Slot 0, envelope1)
    quarantine.addOrphan(Slot 0, envelope2)
    quarantine.addOrphan(Slot 0, envelope3)

    check:
      quarantine.hasOrphan(root1)
      quarantine.hasOrphan(root2)
      quarantine.hasOrphan(root3)
      quarantine.hasOrphan(envelope1)
      quarantine.hasOrphan(envelope2)
      quarantine.hasOrphan(envelope3)

    quarantine.addOrphan(Slot 3, envelope4)
    check:
      not quarantine.hasOrphan(root1)
      quarantine.hasOrphan(root2)
      quarantine.hasOrphan(root3)
      quarantine.hasOrphan(root4)
      not quarantine.hasOrphan(envelope1)
      quarantine.hasOrphan(envelope2)
      quarantine.hasOrphan(envelope3)
      quarantine.hasOrphan(envelope4)

    quarantine.addOrphan(Slot 8, envelope4)
    check:
      not quarantine.hasOrphan(root2)
      not quarantine.hasOrphan(root3)
      quarantine.hasOrphan(root4)
      not quarantine.hasOrphan(envelope2)
      not quarantine.hasOrphan(envelope3)
      quarantine.hasOrphan(envelope4)
