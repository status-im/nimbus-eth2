# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/random,
  unittest2,
  results,
  kzg4844/[kzg_abi, kzg],
  ./consensus_spec/[os_ops, fixtures_utils],
  ../beacon_chain/spec/[helpers, peerdas_helpers],
  ../beacon_chain/spec/datatypes/[fulu, gloas, deneb]

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

type
  BuiltSidecars = object
    commitments: KzgCommitments
    fuluSidecars: seq[fulu.DataColumnSidecar]
    gloasSidecars: seq[gloas.DataColumnSidecar]

proc buildSidecarsFromBlobs(blobs: seq[KzgBlob]): BuiltSidecars =
  ## Build one sidecar per column index for both fulu and gloas variants,
  ## populating only the fields relevant to KZG proof verification.
  var
    allCells = newSeq[array[kzg_abi.CELLS_PER_EXT_BLOB, KzgCell]](blobs.len)
    allProofs = newSeq[array[kzg_abi.CELLS_PER_EXT_BLOB, KzgProof]](blobs.len)
    commitmentsSeq = newSeqOfCap[KzgCommitment](blobs.len)

  for i, blob in blobs:
    let cp = computeCellsAndKzgProofs(blob).valueOr:
      raiseAssert "computeCellsAndKzgProofs failed"
    allCells[i] = cp.cells
    allProofs[i] = cp.proofs
    let c = blobToKzgCommitment(blob).valueOr:
      raiseAssert "blobToKzgCommitment failed"
    commitmentsSeq.add(c)

  let commitments = KzgCommitments.init(commitmentsSeq)

  var
    fuluSidecars =
      newSeqOfCap[fulu.DataColumnSidecar](kzg_abi.CELLS_PER_EXT_BLOB)
    gloasSidecars =
      newSeqOfCap[gloas.DataColumnSidecar](kzg_abi.CELLS_PER_EXT_BLOB)

  for columnIndex in 0 ..< kzg_abi.CELLS_PER_EXT_BLOB:
    var
      col = newSeqOfCap[KzgCell](blobs.len)
      cpr = newSeqOfCap[KzgProof](blobs.len)
    for row in 0 ..< blobs.len:
      col.add(allCells[row][columnIndex])
      cpr.add(allProofs[row][columnIndex])

    fuluSidecars.add fulu.DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(col),
      kzg_commitments: commitments,
      kzg_proofs: deneb.KzgProofs.init(cpr))

    gloasSidecars.add gloas.DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: DataColumn.init(col),
      kzg_proofs: deneb.KzgProofs.init(cpr))

  BuiltSidecars(
    commitments: commitments,
    fuluSidecars: fuluSidecars,
    gloasSidecars: gloasSidecars)

suite "EIP-7594 Unit Tests":
  test "EIP-7594: Compute Matrix":
    proc testComputeExtendedMatrix() =
      var
        rng = initRand(126)
        blob_count = rng.rand(1..(deneb.MAX_BLOB_COMMITMENTS_PER_BLOCK.int))
      let
        input_blobs = createSampleKzgBlobs(blob_count, rng.rand(int))
        extended_matrix = compute_matrix(input_blobs)
      doAssert extended_matrix.get.len == kzg_abi.CELLS_PER_EXT_BLOB * blob_count
      for row in chunks(extended_matrix.get, kzg_abi.CELLS_PER_EXT_BLOB):
        doAssert len(row) == kzg_abi.CELLS_PER_EXT_BLOB
    testComputeExtendedMatrix()

  test "EIP:7594: Recover Matrix":
    proc testRecoverMatrix() =
      var rng = initRand(126)

      # Number of samples we shall be recovering
      const N_SAMPLES = kzg_abi.CELLS_PER_EXT_BLOB div 2

      # Compute an extended matrix with a random
      # blob count for this test
      let
        blob_count = rng.rand(1..(NUMBER_OF_COLUMNS.int))
        blobs = createSampleKzgBlobs(blob_count, rng.rand(int))
        extended_matrix = compute_matrix(blobs)

      # Construct a matrix with some entries missing
      var partial_matrix: seq[MatrixEntry]
      for blob_entries in chunks(extended_matrix.get, kzg_abi.CELLS_PER_EXT_BLOB):
        var blb_entry = blob_entries
        partial_matrix.add(blb_entry[0..N_SAMPLES-1])

      # Given the partial matrix, recover the missing entries
      let recovered_matrix = recover_matrix(partial_matrix, blob_count)

      # Ensure that the recovered matrix matches the original matrix
      doAssert recovered_matrix.get == extended_matrix.get, "Both matrices don't match!"
    testRecoverMatrix()

  test "EIP-7594: Verify DataColumnSidecar KZG Proofs (fulu, single)":
    proc testSingleFulu() =
      var rng = initRand(41)
      let
        blobCount = rng.rand(1..8)
        blobs = createSampleKzgBlobs(blobCount, rng.rand(int))
        built = buildSidecarsFromBlobs(blobs)

      # Every well-formed sidecar verifies individually.
      for s in built.fuluSidecars:
        doAssert verify_data_column_sidecar_kzg_proofs(s).isOk

      # Corrupting a single proof must make verification fail.
      block:
        var sidecar = built.fuluSidecars[0]
        var flipped = sidecar.kzg_proofs.asSeq
        flipped[0].bytes[0] = flipped[0].bytes[0] xor 0xff'u8
        sidecar.kzg_proofs = deneb.KzgProofs.init(flipped)
        doAssert verify_data_column_sidecar_kzg_proofs(sidecar).isErr
    testSingleFulu()

  test "EIP-7594: Verify DataColumnSidecar KZG Proofs (gloas, single)":
    proc testSingleGloas() =
      var rng = initRand(42)
      let
        blobCount = rng.rand(1..8)
        blobs = createSampleKzgBlobs(blobCount, rng.rand(int))
        built = buildSidecarsFromBlobs(blobs)

      # Every well-formed sidecar verifies individually.
      for s in built.gloasSidecars:
        doAssert verify_data_column_sidecar_kzg_proofs(
          s, built.commitments).isOk

      # Corrupting a single proof must make verification fail.
      block:
        var sidecar = built.gloasSidecars[0]
        var flipped = sidecar.kzg_proofs.asSeq
        flipped[0].bytes[0] = flipped[0].bytes[0] xor 0xff'u8
        sidecar.kzg_proofs = deneb.KzgProofs.init(flipped)
        doAssert verify_data_column_sidecar_kzg_proofs(
          sidecar, built.commitments).isErr

      # Mismatched commitments length is rejected.
      block:
        let
          sidecar = built.gloasSidecars[0]
          fullCommitments = built.commitments.asSeq
          shortened = fullCommitments[0 ..< fullCommitments.len - 1]
        doAssert verify_data_column_sidecar_kzg_proofs(
          sidecar, KzgCommitments.init(shortened)).isErr
    testSingleGloas()

  test "EIP-7594: Batch Verify DataColumnSidecar KZG Proofs (fulu)":
    proc testBatchFulu() =
      var rng = initRand(43)
      let
        blobCount = rng.rand(1..8)
        blobs = createSampleKzgBlobs(blobCount, rng.rand(int))
        built = buildSidecarsFromBlobs(blobs)
        sidecars = built.fuluSidecars

      # Valid batch verifies successfully.
      doAssert verify_data_column_sidecar_kzg_proofs(sidecars).isOk

      # A partial slice of a valid batch must also verify.
      doAssert verify_data_column_sidecar_kzg_proofs(
        sidecars[0 ..< sidecars.len div 2]).isOk

      # Empty batch is trivially ok.
      doAssert verify_data_column_sidecar_kzg_proofs(
        newSeq[fulu.DataColumnSidecar](0)).isOk

      # Corrupting a proof anywhere in the batch must fail the whole batch.
      block:
        var corrupted = sidecars
        var flipped = corrupted[0].kzg_proofs.asSeq
        flipped[0].bytes[0] = flipped[0].bytes[0] xor 0xff'u8
        corrupted[0].kzg_proofs = deneb.KzgProofs.init(flipped)
        doAssert verify_data_column_sidecar_kzg_proofs(corrupted).isErr

      # Mismatched column / commitments / proofs lengths are rejected.
      block:
        var lenMismatch = sidecars
        let
          fullCommitments = lenMismatch[0].kzg_commitments.asSeq
          shortened = fullCommitments[0 ..< fullCommitments.len - 1]
        lenMismatch[0].kzg_commitments = KzgCommitments.init(shortened)
        doAssert verify_data_column_sidecar_kzg_proofs(lenMismatch).isErr
    testBatchFulu()

  test "EIP-7594: Batch Verify DataColumnSidecar KZG Proofs (gloas)":
    proc testBatchGloas() =
      var rng = initRand(44)
      let
        blobCount = rng.rand(1..8)
        blobs = createSampleKzgBlobs(blobCount, rng.rand(int))
        built = buildSidecarsFromBlobs(blobs)
        sidecars = built.gloasSidecars
        commitments = built.commitments

      # Valid batch verifies successfully.
      doAssert verify_data_column_sidecar_kzg_proofs(sidecars, commitments).isOk

      # A partial slice of a valid batch must also verify.
      doAssert verify_data_column_sidecar_kzg_proofs(
        sidecars[0 ..< sidecars.len div 2], commitments).isOk

      # Empty batch is trivially ok.
      doAssert verify_data_column_sidecar_kzg_proofs(
        newSeq[gloas.DataColumnSidecar](0), commitments).isOk

      # Corrupting a proof anywhere in the batch must fail the whole batch.
      block:
        var corrupted = sidecars
        var flipped = corrupted[0].kzg_proofs.asSeq
        flipped[0].bytes[0] = flipped[0].bytes[0] xor 0xff'u8
        corrupted[0].kzg_proofs = deneb.KzgProofs.init(flipped)
        doAssert verify_data_column_sidecar_kzg_proofs(
          corrupted, commitments).isErr

      # Mismatched column / commitments lengths are rejected.
      block:
        let
          fullCommitments = commitments.asSeq
          shortened = fullCommitments[0 ..< fullCommitments.len - 1]
        doAssert verify_data_column_sidecar_kzg_proofs(
          sidecars, KzgCommitments.init(shortened)).isErr
    testBatchGloas()

doAssert freeTrustedSetup().isOk
