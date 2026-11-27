# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/datatypes/deneb,
  ../beacon_chain/rpc/rest_utils

func makeBlobs(tags: openArray[byte]): seq[deneb.Blob] =
  # A `Blob` is 128 KiB: fill the blobs in place on the heap and compare them
  # as seqs, because `Blob` temporaries on the stack exceed the stack usage
  # limit of the CI build
  var res = newSeq[deneb.Blob](tags.len)
  for i, tag in tags:
    res[i][0] = tag
  res

func makeHash(tag: byte): VersionedHash =
  var res: VersionedHash
  res.data[0] = 0x01
  res.data[1] = tag
  res

suite "REST API utilities":
  setup:
    # Block with blobs A, B, A: the commitment of A appears at two indices
    let
      blobs = makeBlobs([1'u8, 2, 1])
      blobHashes = @[makeHash(1), makeHash(2), makeHash(1)]

  test "selectBlobs returns one blob per requested versioned hash":
    let res = selectBlobs(blobs, blobHashes, [makeHash(1)]).asSeq
    check res == blobs[0 .. 0]

  test "selectBlobs ignores repeated versioned hashes in the request":
    let res = selectBlobs(blobs, blobHashes, [makeHash(1), makeHash(1)]).asSeq
    check res == blobs[0 .. 0]

  test "selectBlobs orders blobs by first occurrence in the block":
    let res = selectBlobs(
      blobs, blobHashes, [makeHash(2), makeHash(3), makeHash(1)]).asSeq
    check res == blobs[0 .. 1]
