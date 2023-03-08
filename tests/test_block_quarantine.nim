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
  var
    b = phase0.SignedBeaconBlock(
      message: phase0.BeaconBlock(slot: slot, parent_root: parent))
  b.root = hash_tree_root(b.message)
  ForkedSignedBeaconBlock.init(b)

suite "Block quarantine":
  test "Unviable smoke test":
    let
      b0 = makeBlock(Slot 0, ZERO_HASH)
      b1 = makeBlock(Slot 1, b0.root)
      b2 = makeBlock(Slot 2, b1.root)
      b3 = makeBlock(Slot 3, b2.root)
      b4 = makeBlock(Slot 4, b2.root)

    var quarantine: Quarantine

    quarantine.addMissing(b1.root)
    check:
      FetchRecord(root: b1.root) in quarantine.checkMissing()

      quarantine.addOrphan(Slot 0, b1)

      FetchRecord(root: b1.root) notin quarantine.checkMissing()

      quarantine.addOrphan(Slot 0, b2)
      quarantine.addOrphan(Slot 0, b3)
      quarantine.addOrphan(Slot 0, b4)

      (b4.root, ValidatorSig()) in quarantine.orphans

    quarantine.addUnviable(b4.root)

    check:
      (b4.root, ValidatorSig()) notin quarantine.orphans

    quarantine.addUnviable(b1.root)

    check:
      (b1.root, ValidatorSig()) notin quarantine.orphans
      (b2.root, ValidatorSig()) notin quarantine.orphans
      (b3.root, ValidatorSig()) notin quarantine.orphans
