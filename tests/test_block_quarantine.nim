# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../beacon_chain/spec/forks,
  ../beacon_chain/spec/datatypes/[phase0, deneb],
  ../beacon_chain/consensus_object_pools/block_quarantine

func makeBlock(slot: Slot, parent: Eth2Digest): ForkedSignedBeaconBlock =
  var b = phase0.SignedBeaconBlock(
    message: phase0.BeaconBlock(slot: slot, parent_root: parent)
  )
  b.root = hash_tree_root(b.message)
  ForkedSignedBeaconBlock.init(b)

func makeBlobbyBlock(slot: Slot, parent: Eth2Digest): deneb.SignedBeaconBlock =
  var b =
    deneb.SignedBeaconBlock(message: deneb.BeaconBlock(slot: slot, parent_root: parent))
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

    var quarantine: Quarantine

    quarantine.addMissing(b1.root)
    check:
      FetchRecord(root: b1.root) in quarantine.checkMissing(32)

      quarantine.addOrphan(Slot 0, b1).isOk

      FetchRecord(root: b1.root) notin quarantine.checkMissing(32)

      quarantine.addOrphan(Slot 0, b2).isOk
      quarantine.addOrphan(Slot 0, b3).isOk
      quarantine.addOrphan(Slot 0, b4).isOk

      quarantine.addBlobless(Slot 0, b5)
      quarantine.addBlobless(Slot 0, b6)

      (b4.root, ValidatorSig()) in quarantine.orphans
      b5.root in quarantine.blobless
      b6.root in quarantine.blobless

    quarantine.addUnviable(b4.root)

    check:
      (b4.root, ValidatorSig()) notin quarantine.orphans

      b5.root in quarantine.blobless
      b6.root notin quarantine.blobless

    quarantine.addUnviable(b1.root)

    check:
      (b1.root, ValidatorSig()) notin quarantine.orphans
      (b2.root, ValidatorSig()) notin quarantine.orphans
      (b3.root, ValidatorSig()) notin quarantine.orphans

      b5.root notin quarantine.blobless
      b6.root notin quarantine.blobless
