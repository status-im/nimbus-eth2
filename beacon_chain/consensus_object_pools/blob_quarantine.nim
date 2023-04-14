# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/tables,
  ../spec/datatypes/deneb


const
  MaxBlobs = SLOTS_PER_EPOCH * MAX_BLOBS_PER_BLOCK


type
  BlobQuarantine* = object
    blobs*: Table[(Eth2Digest, BlobIndex), ref BlobSidecar]


func put*(quarantine: var BlobQuarantine, blobSidecar: ref BlobSidecar) =
  if quarantine.blobs.lenu64 > MaxBlobs:
    return
  discard quarantine.blobs.hasKeyOrPut((blobSidecar.block_root,
                                        blobSidecar.index), blobSidecar)

func blobIndices*(quarantine: BlobQuarantine, digest: Eth2Digest):
     seq[BlobIndex] =
  var r: seq[BlobIndex] = @[]
  for i in 0..MAX_BLOBS_PER_BLOCK-1:
    if quarantine.blobs.hasKey((digest, i)):
      r.add(i)
  r

func hasBlob*(quarantine: BlobQuarantine, blobSidecar: BlobSidecar) : bool =
  quarantine.blobs.hasKey((blobSidecar.block_root, blobSidecar.index))

func popBlobs*(quarantine: var BlobQuarantine, digest: Eth2Digest):
     seq[ref BlobSidecar] =
  var r: seq[ref BlobSidecar] = @[]
  for i in 0..MAX_BLOBS_PER_BLOCK-1:
    var b: ref BlobSidecar
    if quarantine.blobs.pop((digest, i), b):
      r.add(b)
  r

func peekBlobs*(quarantine: var BlobQuarantine, digest: Eth2Digest):
     seq[ref BlobSidecar] =
  var r: seq[ref BlobSidecar] = @[]
  for i in 0..MAX_BLOBS_PER_BLOCK-1:
    quarantine.blobs.withValue((digest, i), value):
      r.add(value[])
  r

func removeBlobs*(quarantine: var BlobQuarantine, digest: Eth2Digest) =
  for i in 0..MAX_BLOBS_PER_BLOCK-1:
    quarantine.blobs.del((digest, i))

func hasBlobs*(quarantine: BlobQuarantine, blck: deneb.SignedBeaconBlock):
     bool =
  let idxs = quarantine.blobIndices(blck.root)
  if len(blck.message.body.blob_kzg_commitments) != len(idxs):
    return false
  for i in 0..len(idxs):
    if idxs[i] != uint64(i):
      return false
  true
