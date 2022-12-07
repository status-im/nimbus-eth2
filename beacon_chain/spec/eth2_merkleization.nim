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
  ./ssz_codec

from ./datatypes/phase0 import HashedBeaconState, SignedBeaconBlock
from ./datatypes/altair import HashedBeaconState, SignedBeaconBlock
from ./datatypes/bellatrix import HashedBeaconState, SignedBeaconBlock
from ./datatypes/capella import HashedBeaconState, SignedBeaconBlock

export ssz_codec, merkleization, proofs

type
  DepositsMerkleizer* = SszMerkleizer[DEPOSIT_CONTRACT_LIMIT]

# Can't use `ForkyHashedBeaconState`/`ForkyHashedSignedBeaconBlock` without
# creating recursive module dependency through `forks`.
func hash_tree_root*(
    x: phase0.HashedBeaconState | altair.HashedBeaconState |
       bellatrix.HashedBeaconState | capella.HashedBeaconState) {.
  error: "HashedBeaconState should not be hashed".}

func hash_tree_root*(
    x: phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
       bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock) {.
  error: "SignedBeaconBlock should not be hashed".}

func depositCountBytes*(x: uint64): array[32, byte] =
  doAssert(x <= 4294967295'u64)
  var z = x
  for i in 0..3:
    result[31-i] = byte(int64(z) %% 256'i64)
    z = z div 256

func depositCountU64*(xs: openArray[byte]): uint64 =
  ## depositCountU64 considers just the first 4 bytes as
  ## MAX_DEPOSIT_COUNT is defined as 2^32 - 1.
  for i in 0 .. 27:
    doAssert xs[i] == 0
  return uint64.fromBytesBE(xs[24..31])

func init*(T: type DepositsMerkleizer, s: DepositContractState): DepositsMerkleizer =
  let count = depositCountU64(s.deposit_count)
  DepositsMerkleizer.init(s.branch, count)

func toDepositContractState*(merkleizer: DepositsMerkleizer): DepositContractState =
  # TODO There is an off by one discrepancy in the size of the arrays here that
  #      need to be investigated. It shouldn't matter as long as the tree is
  #      not populated to its maximum size.
  result.branch[0..31] = merkleizer.getCombinedChunks[0..31]
  result.deposit_count[24..31] = merkleizer.getChunkCount().toBytesBE
