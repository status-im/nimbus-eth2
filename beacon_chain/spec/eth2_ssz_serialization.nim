# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# Import this module to get access to `SSZ.encode` and `SSZ.decode` for spec types

import
  ./ssz_codec,
  ../ssz/ssz_serialization,
  ./datatypes/[phase0, altair],
  ./eth2_merkleization

export phase0, altair, ssz_codec, ssz_serialization, eth2_merkleization

proc readAndUpdateRoot(data: openArray[byte], val: var auto, updateRoot = true) {.
     raises: [Defect, MalformedSszError, SszSizeMismatchError].} =
  readSszValue(data, val)
  if updateRoot:
    val.root = hash_tree_root(val.message)

# TODO this is an ugly way to get a stronger match than the generic readSszBytes
# and avoid ambiguities - `var` + typeclasses are problematic

template readSszBytes*(
    data: openArray[byte], val: var phase0.SignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var phase0.TrustedSignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var altair.SignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var altair.TrustedSignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
