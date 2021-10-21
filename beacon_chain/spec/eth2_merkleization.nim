# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# Import this module to get access to `hash_tree_root` for spec types

import
  ssz_serialization/merkleization,
  ./ssz_codec,
  ./datatypes/[phase0, altair]

export ssz_codec, merkleization

func hash_tree_root*(x: phase0.HashedBeaconState | altair.HashedBeaconState) {.
  error: "HashedBeaconState should not be hashed".}

func hash_tree_root*(x: phase0.SomeSignedBeaconBlock | altair.SomeSignedBeaconBlock) {.
  error: "SignedBeaconBlock should not be hashed".}
