# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

# Uncategorized helper functions from the spec
import
  unittest2,
  random,
  std/[algorithm, macros, tables, sysrand],
  stew/results,
  stint,
  kzg4844/[kzg_abi, kzg_ex],
  ssz_serialization/proofs,
  chronicles,
  ../beacon_chain/spec/beacon_time,
  eth/p2p/discoveryv5/[node],
  ./consensus_spec/[os_ops, fixtures_utils],
  ../beacon_chain/spec/[helpers, eip7594_helpers],
  ../beacon_chain/spec/datatypes/[eip7594, deneb]

from std/sequtils import anyIt, mapIt, toSeq
from std/strutils import rsplit

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert Kzg.loadTrustedSetup(
    sourceDir &
      "/../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt").isOk

const MAX_TOP_BYTE = 114

proc createSampleKzgBlobs(n: int): Result[seq[KzgBlob], cstring] =
  var blob: KzgBlob
  var blobs: seq[KzgBlob]
  for i in 0..<n:
    discard urandom(blob)
    for i in 0..<blob.len:
      if blob[i] > MAX_TOP_BYTE and i %% kzg_abi.BYTES_PER_FIELD_ELEMENT == 0:
        blob[i] = MAX_TOP_BYTE
    blobs.add(blob)

  ok(blobs)

proc chunks[T](lst: seq[T], n: int): seq[seq[T]] =
    ## Helper that splits a list into N sized chunks.
    result = @[]
    for i in countup(0, len(lst) - 1, n):
        result.add(lst[i..min(i + n - 1, len(lst) - 1)])

suite "EIP-7594 Unit Tests":
  test "EIP-7594: Compute Extended Matrix":
    proc testComputeExtendedMatrix() =
      let 
        blob_count = 2
        input_blobs = createSampleKzgBlobs(blob_count)
        extended_matrix = compute_extended_matrix(input_blobs.get)
      doAssert extended_matrix.get.len == kzg_abi.CELLS_PER_EXT_BLOB * blob_count
      let
        chunkSize = kzg_abi.CELLS_PER_EXT_BLOB
        rows = chunks(extended_matrix.get.asSeq, kzg_abi.CELLS_PER_EXT_BLOB)
      for row in rows:
        doAssert len(row) == kzg_abi.CELLS_PER_EXT_BLOB
    testComputeExtendedMatrix()

  test "EIP:7594: Recover Matrix":
    proc testRecoverMatrix() =
      var rng = initRand(5566)

      # Number of samples we shall be recovering
      const N_SAMPLES = kzg_abi.CELLS_PER_EXT_BLOB div 2

      # Compute an extended matrix with 2 blobs for this test
      let
        blob_count = 2
        blobs = createSampleKzgBlobs(blob_count)
        extended_matrix = compute_extended_matrix(blobs.get)
      
      # Construct a matrix with some entries missing
      var partial_matrix: ExtendedMatrix
      for blob_entries in chunks(extended_matrix.get.asSeq, kzg_abi.CELLS_PER_EXT_BLOB):
        var blb_entry = blob_entries
        rng.shuffle(blb_entry)
        discard partial_matrix.add(blob_entries[0..N_SAMPLES-1])

      # Given the partial matrix, now recover the missing entries
      let recovered_matrix = recover_matrix(partial_matrix, CellID(blob_count))


      

