# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# This module exports SSZ.encode and SSZ.decode for spec types - don't use
# ssz_serialization directly! To bypass root updates, use `readSszBytes`
# without involving SSZ!
import
  ssz_serialization,
  ./ssz_codec,
  ./datatypes/[phase0, altair, bellatrix, capella],
  ./eth2_merkleization

from ./datatypes/deneb import SignedBeaconBlock, TrustedSignedBeaconBlock

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
template readSszBytes*(
    data: openArray[byte], val: var bellatrix.SignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var bellatrix.TrustedSignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var capella.SignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var capella.TrustedSignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var deneb.SignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)
template readSszBytes*(
    data: openArray[byte], val: var deneb.TrustedSignedBeaconBlock, updateRoot = true) =
  readAndUpdateRoot(data, val, updateRoot)

template readSszBytes*(
    data: openArray[byte], val: var auto, updateRoot: bool) =
  readSszValue(data, val)

func readSszBytes(T: type, data: openArray[byte], updateRoot = true): T {.
    raises: [Defect, MalformedSszError, SszSizeMismatchError].} =
  var res: T
  readSszBytes(data, res, updateRoot)
  res
