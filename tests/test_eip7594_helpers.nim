# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  random,
  unittest2,
  results,
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

# 114 is the MSB (most/max significant byte)
# such that BLS modulus does not overflow
const MAX_TOP_BYTE = 114

proc createSampleKzgBlobs(n: int, seed: int): seq[KzgBlob] =
  var
    blobs: seq[KzgBlob] = @[]
    # Initialize the PRNG with the given seed
    rng = initRand(seed)
  for blobIndex in 0..<n:
    var blob: array[int(BYTES_PER_BLOB), byte]
    # Fill the blob with random bytes using the seeded PRNG
    for byteIndex in 0..<int(BYTES_PER_BLOB):
      blob[byteIndex] = rng.rand(byte)
    # Adjust bytes according to the given condition
    for byteIndex in 0..<int(BYTES_PER_BLOB):
      if blob[byteIndex] > MAX_TOP_BYTE and
         byteIndex mod kzg_abi.BYTES_PER_FIELD_ELEMENT == 0:
        blob[byteIndex] = MAX_TOP_BYTE
    blobs.add(KzgBlob(bytes: blob))
  blobs

iterator chunks[T](lst: seq[T], n: int): seq[T] =
  ## Iterator that yields N-sized chunks from the list.
  for i in countup(0, len(lst) - 1, n):
    yield lst[i..min(i + n - 1, len(lst) - 1)]

suite "EIP-7594 Unit Tests":
  test "EIP-7594: Compute Matrix":
    proc testComputeExtendedMatrix() =
      const 
        blob_count = 2
      let
        input_blobs = createSampleKzgBlobs(blob_count, 123456)
        extended_matrix = compute_matrix(input_blobs)
      doAssert extended_matrix.get.len == kzg_abi.CELLS_PER_EXT_BLOB * blob_count
      for row in chunks(extended_matrix.get, kzg_abi.CELLS_PER_EXT_BLOB):
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