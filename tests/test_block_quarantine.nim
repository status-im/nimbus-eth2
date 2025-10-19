# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/[forks, presets],
  ../beacon_chain/spec/datatypes/[phase0, deneb],
  ../beacon_chain/consensus_object_pools/block_quarantine

func makeBlock(slot: Slot, parent: Eth2Digest): ForkedSignedBeaconBlock =
  var
    b = phase0.SignedBeaconBlock(
      message: phase0.BeaconBlock(slot: slot, parent_root: parent))
  b.root = hash_tree_root(b.message)
  ForkedSignedBeaconBlock.init(b)

func makeBlobbyBlock(slot: Slot, parent: Eth2Digest): deneb.SignedBeaconBlock =
  var
    b = deneb.SignedBeaconBlock(
      message: deneb.BeaconBlock(slot: slot, parent_root: parent))
  b.root = hash_tree_root(b.message)
  b

suite "Block quarantine":
  test "Unviable smoke test":
    let
      b0 = makeBlock(Slot 0, ZERO_HASH)
      b1 = makeBlock(Slot 1, b0.root)
      b2 = makeBlock(Slot 2, b1.root)
      b3 = makeBlock(Slot 3, b2.root)
      b4 = makeBlock(Slot 4, b2.root)
      b5 = makeBlobbyBlock(Slot 4, b3.root)
      b6 = makeBlobbyBlock(Slot 4, b4.root)

    var quarantine = Quarantine.init(defaultRuntimeConfig)

    quarantine.addMissing(b1.root)
    check:
      FetchRecord(root: b1.root) in quarantine.checkMissing(32)

      quarantine.addOrphan(Slot 0, b1).isOk

      FetchRecord(root: b1.root) notin quarantine.checkMissing(32)

      quarantine.addOrphan(Slot 0, b2).isOk
      quarantine.addOrphan(Slot 0, b3).isOk
      quarantine.addOrphan(Slot 0, b4).isOk

      quarantine.addSidecarless(Slot 0, b5)
      quarantine.addSidecarless(Slot 0, b6)

      (b4.root, ValidatorSig()) in quarantine.orphans
      b5.root in quarantine.sidecarless
      b6.root in quarantine.sidecarless

    quarantine.addUnviable(b4.root)

    check:
      (b4.root, ValidatorSig()) notin quarantine.orphans

      b5.root in quarantine.sidecarless
      b6.root notin quarantine.sidecarless

    quarantine.addUnviable(b1.root)

    check:
      (b1.root, ValidatorSig()) notin quarantine.orphans
      (b2.root, ValidatorSig()) notin quarantine.orphans
      (b3.root, ValidatorSig()) notin quarantine.orphans

      b5.root notin quarantine.sidecarless
      b6.root notin quarantine.sidecarless

  test "Recursive missing parent":
    let
      b0 = makeBlock(Slot 0, ZERO_HASH)
      b1 = makeBlock(Slot 1, b0.root)
      b2 = makeBlock(Slot 2, b1.root)

    var quarantine = Quarantine.init(defaultRuntimeConfig)
    check:
      b0.root notin quarantine.missing
      b1.root notin quarantine.missing
      b2.root notin quarantine.missing

      # Add b2
      quarantine.addOrphan(Slot 0, b2).isOk
      b0.root notin quarantine.missing
      b1.root in quarantine.missing
      b2.root notin quarantine.missing

      # Add b1
      quarantine.addOrphan(Slot 0, b1).isOk
      b0.root in quarantine.missing
      b1.root notin quarantine.missing
      b2.root notin quarantine.missing

      # Re-add b2
      quarantine.addOrphan(Slot 0, b2).isOk
      b0.root in quarantine.missing
      b1.root notin quarantine.missing
      b2.root notin quarantine.missing

    # Empty missing
    while quarantine.missing.len > 0:
      discard quarantine.checkMissing(max = 5)

    check:
      # Re-add b2
      quarantine.addOrphan(Slot 0, b2).isOk
      b0.root in quarantine.missing
      b1.root notin quarantine.missing
      b2.root notin quarantine.missing

  test "Keep downloading parent chain even if we hit missing limit":
    var quarantine = Quarantine.init(defaultRuntimeConfig)
    var blocks = @[makeBlock(Slot 0, ZERO_HASH)]
    for i in 0..<MaxMissingItems:
      blocks.add makeBlock(blocks[^1].slot + 1, blocks[^1].root)

    # Fill missing list with junk
    for i in 0..<MaxMissingItems:
      quarantine.addMissing(blocks[^(i + 1)].root)

    check:
      blocks[0].root notin quarantine.missing
      quarantine.addOrphan(Slot 0, blocks[1]) == Result[void, cstring].ok()
      blocks[0].root in quarantine.missing

  test "Don't re-download unviable blocks":
    var quarantine = Quarantine.init(defaultRuntimeConfig)
    let
      b0 = makeBlock(Slot 0, ZERO_HASH)
      b1 = makeBlock(Slot 1, b0.root)
      b2 = makeBlock(Slot 2, b1.root)

    quarantine.addMissing(b1.root)
    quarantine.addMissing(b2.root)

    check:
      b2.root in quarantine.missing

    quarantine.addUnviable(b1.root)
    check:
      b1.root notin quarantine.missing

    check:
      quarantine.addOrphan(Slot 0, b2).isErr()
      b2.root notin quarantine.missing
