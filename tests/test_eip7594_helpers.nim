# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  std/[macros, tables, sysrand],
  results,
  stint,
  kzg4844/[kzg_abi, kzg],
  ./consensus_spec/[os_ops, fixtures_utils],
  ../beacon_chain/spec/[helpers, eip7594_helpers],
  ../beacon_chain/spec/datatypes/[eip7594, deneb]

from std/strutils import rsplit

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert loadTrustedSetup(
    sourceDir &
      "/../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt", 0).isOk

const MAX_TOP_BYTE = 114

proc createSampleKzgBlobs(n: int): seq[KzgBlob] =
  var
    blob: array[BYTES_PER_BLOB, byte]
    blobs: seq[KzgBlob]
  for i in 0..<n:
    discard urandom(blob)
    for i in 0..<BYTES_PER_BLOB.int:
      if blob[i] > MAX_TOP_BYTE and i %% kzg_abi.BYTES_PER_FIELD_ELEMENT == 0:
        blob[i] = MAX_TOP_BYTE
    blobs.add(KzgBlob(bytes: blob))

  blobs

proc chunks[T](lst: seq[T], n: int): seq[seq[T]] =
    ## Helper that splits a list into N sized chunks.
    result = @[]
    for i in countup(0, len(lst) - 1, n):
        result.add(lst[i..min(i + n - 1, len(lst) - 1)])

suite "EIP-7594 Unit Tests":
  test "EIP-7594: Compute Matrix":
    proc testComputeExtendedMatrix() =
      const 
        blob_count = 2
      let
        input_blobs = createSampleKzgBlobs(blob_count)
        extended_matrix = compute_matrix(input_blobs)
      doAssert extended_matrix.get.len == kzg_abi.CELLS_PER_EXT_BLOB * blob_count
      let rows = chunks(extended_matrix.get, kzg_abi.CELLS_PER_EXT_BLOB)
      for row in rows:
        doAssert len(row) == kzg_abi.CELLS_PER_EXT_BLOB
    testComputeExtendedMatrix()


suite "EIP-7594 Sampling Tests":
  test "EIP7594: Extended Sample Count":
    proc testExtendedSampleCount() =
      let samplesPerSlot = 16
      const tests = [
        (0, 16),
        (1, 20),
        (2, 24),
        (3, 27),
        (4, 29),
        (5, 32),
        (6, 35),
        (7, 37),
        (8, 40),
        (9, 42),
        (10, 44),
        (11, 47),
        (12, 49),
        (13, 51),
        (14, 53),
        (15, 55),
        (16, 57),
        (17, 59),
        (18, 61),
        (19, 63),
        (20, 65)
      ]

      for (allowed_failures, extendedSampleCount) in tests:
        check: get_extended_sample_count(
            samplesPerSlot, allowed_failures) == extendedSampleCount
    testExtendedSampleCount()

doAssert freeTrustedSetup().isOk