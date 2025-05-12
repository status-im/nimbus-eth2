# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Import this module to get access to `hash_tree_root` for spec types

import
  std/sets,
  ssz_serialization/[merkleization, proofs],
  ./ssz_codec

from ./datatypes/base import HashedValidatorPubKeyItem
from ./datatypes/phase0 import HashedBeaconState, SignedBeaconBlock
from ./datatypes/altair import HashedBeaconState, SignedBeaconBlock
from ./datatypes/bellatrix import HashedBeaconState, SignedBeaconBlock
from ./datatypes/capella import HashedBeaconState, SignedBeaconBlock
from ./datatypes/deneb import HashedBeaconState, SignedBeaconBlock
from ./datatypes/electra import HashedBeaconState, SignedBeaconBlock
from ./datatypes/fulu import HashedBeaconState, SignedBeaconBlock

export ssz_codec, merkleization, proofs

# Can't use `ForkyHashedBeaconState`/`ForkyHashedSignedBeaconBlock` without
# creating recursive module dependency through `forks`.
func hash_tree_root*(
    x: phase0.HashedBeaconState | altair.HashedBeaconState |
       bellatrix.HashedBeaconState | capella.HashedBeaconState |
       deneb.HashedBeaconState | electra.HashedBeaconState |
       fulu.HashedBeaconState) {.
  error: "HashedBeaconState should not be hashed".}

func hash_tree_root*(
    x: phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
       bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
       deneb.SignedBeaconBlock | electra.SignedBeaconBlock |
       fulu.SignedBeaconBlock) {.
  error: "SignedBeaconBlock should not be hashed".}

func hash*(v: ref HashedValidatorPubKeyItem): Hash =
  if not isNil(v):
    hash(v[].key)
  else:
    default(Hash)

func `==`*(a, b: ref HashedValidatorPubKeyItem): bool =
  if isNil(a):
    isNil(b)
  elif isNil(b):
    false
  else:
    a[].key == b[].key

func init*(T: type HashedValidatorPubKey, key: ValidatorPubKey): HashedValidatorPubKey =
  {.noSideEffect.}:
    var keys {.threadvar.}: HashSet[ref HashedValidatorPubKeyItem]

    let
      tmp = (ref HashedValidatorPubKeyItem)(
        key: key,
        root: hash_tree_root(key)
      )
      cached =
        if keys.containsOrIncl(tmp):
          try:
            # The interface of HashSet is such that we must construct a full
            # instance to check if it's in the set - then we can return that
            # instace and discard the one we just created temporarily
            addr keys[tmp][]
          except KeyError:
            raiseAssert "just checked"
        else:
          addr tmp[]

  HashedValidatorPubKey(value: cached)  # https://github.com/nim-lang/Nim/issues/23505
