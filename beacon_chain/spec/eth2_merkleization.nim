# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

# Import this module to get access to `hash_tree_root` for spec types

import
  ssz_serialization/[merkleization, proofs],
  ./ssz_codec,
  ./datatypes/[phase0, altair]

export ssz_codec, merkleization, proofs

type
  DepositsMerkleizer* = SszMerkleizer[DEPOSIT_CONTRACT_LIMIT]

func hash_tree_root*(x: phase0.HashedBeaconState | altair.HashedBeaconState) {.
  error: "HashedBeaconState should not be hashed".}

func hash_tree_root*(x: phase0.SomeSignedBeaconBlock | altair.SomeSignedBeaconBlock) {.
  error: "SignedBeaconBlock should not be hashed".}

func depositCountU64(s: DepositContractState): uint64 =
  for i in 0 .. 23:
    doAssert s.deposit_count[i] == 0

  uint64.fromBytesBE s.deposit_count.toOpenArray(24, 31)

func init*(T: type DepositsMerkleizer, s: DepositContractState): DepositsMerkleizer =
  DepositsMerkleizer.init(s.branch, s.depositCountU64)

func toDepositContractState*(merkleizer: DepositsMerkleizer): DepositContractState =
  # TODO There is an off by one discrepancy in the size of the arrays here that
  #      need to be investigated. It shouldn't matter as long as the tree is
  #      not populated to its maximum size.
  result.branch[0..31] = merkleizer.getCombinedChunks[0..31]
  result.deposit_count[24..31] = merkleizer.getChunkCount().toBytesBE
