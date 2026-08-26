# beacon_chain
# Copyright (c) 2024-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/random,
  chronicles,
  chronos,
  taskpools,
  unittest2,
  results,
  kzg4844/[kzg_abi, kzg],
  ./consensus_spec/[os_ops, fixtures_utils],
  ../beacon_chain/spec/[helpers, peerdas_helpers],
  ../beacon_chain/spec/datatypes/[deneb, fulu, gloas]

from std/strutils import rsplit

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert loadTrustedSetup(
    sourceDir &
      "/../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt", 7).isOk

# 114 is the MSB (most/max significant byte)
# such that BLS modulus does not overflow
const MAX_TOP_BYTE = 114

func createSampleKzgBlobs(n: int, seed: int): seq[KzgBlob] =
  var
    blobs: seq[KzgBlob]
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
    commitments: gloas.KzgCommitments
    fuluSidecars: seq[fulu.DataColumnSidecar]
    gloasSidecars: seq[gloas.DataColumnSidecar]

proc buildSidecarsFromBlobs(blobs: seq[KzgBlob]): BuiltSidecars =
  ## Build one sidecar per column index for both fulu and gloas variants,
  ## populating only the fields relevant to KZG proof verification.
  var
    allCells = newSeq[array[kzg_abi.CELLS_PER_EXT_BLOB, KzgCell]](blobs.len)
    allProofs = newSeq[array[kzg_abi.CELLS_PER_EXT_BLOB, KzgProof]](blobs.len)
    commitments = newSeqOfCap[KzgCommitment](blobs.len)

  for i, blob in blobs:
    let cp = computeCellsAndKzgProofs(blob)
    doAssert cp.isOk, "computeCellsAndKzgProofs failed"
    cp.isErrOr:
      allCells[i] = value.cells
      allProofs[i] = value.proofs
    let c = blobToKzgCommitment(blob).valueOr:
      raiseAssert "blobToKzgCommitment failed"
    commitments.add(c)

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
      kzg_commitments: deneb.KzgCommitments.init(commitments),
      kzg_proofs: deneb.KzgProofs.init(cpr))

    gloasSidecars.add gloas.DataColumnSidecar(
      index: ColumnIndex(columnIndex),
      column: col,
      kzg_proofs: cpr)

  BuiltSidecars(
    commitments: commitments,
    fuluSidecars: fuluSidecars,
    gloasSidecars: gloasSidecars)

suite "EIP-7594 Unit Tests":
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
        var flipped = sidecar.kzg_proofs
        flipped[0].bytes[0] = flipped[0].bytes[0] xor 0xff'u8
        sidecar.kzg_proofs = flipped
        doAssert verify_data_column_sidecar_kzg_proofs(
          sidecar, built.commitments).isErr

      # Mismatched commitments length is rejected.
      block:
        let
          sidecar = built.gloasSidecars[0]
          fullCommitments = built.commitments.asSeq
          shortened = fullCommitments[0 ..< fullCommitments.len - 1]
        doAssert verify_data_column_sidecar_kzg_proofs(
          sidecar, deneb.KzgCommitments.init(shortened)).isErr
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
        var flipped = corrupted[0].kzg_proofs
        flipped[0].bytes[0] = flipped[0].bytes[0] xor 0xff'u8
        corrupted[0].kzg_proofs = flipped
        doAssert verify_data_column_sidecar_kzg_proofs(
          corrupted, commitments).isErr

      # Mismatched column / commitments lengths are rejected.
      block:
        let
          fullCommitments = commitments.asSeq
          shortened = fullCommitments[0 ..< fullCommitments.len - 1]
        doAssert verify_data_column_sidecar_kzg_proofs(
          sidecars, deneb.KzgCommitments.init(shortened)).isErr
    testBatchGloas()

  test "KZG: Recover Cells And Kzg Proofs Parallel - valid":
    proc testRecoverParallelValid() =
      var rng = initRand(126)
      let
        blob_count = rng.rand(1..8)
        blobs = createSampleKzgBlobs(blob_count, rng.rand(int))
        built = buildSidecarsFromBlobs(blobs)

      # Half the columns is enough to recover the rest
      var colInput = newSeq[ref gloas.DataColumnSidecar]()
      for columnIndex in countup(0, kzg_abi.CELLS_PER_EXT_BLOB - 1, 2):
        colInput.add((ref gloas.DataColumnSidecar)(
          index: ColumnIndex(columnIndex),
          column: built.gloasSidecars[columnIndex].column))

      var tp =
        try: Taskpool.new()
        except CatchableError as exc: raiseAssert exc.msg
      defer: tp.shutdown()
      let recovered = (waitFor tp.recover_cells_and_proofs_parallel(colInput)).valueOr:
        raiseAssert "recover_cells_and_proofs_parallel failed"

      # The recovered cells and proofs must match the originals for each blob
      doAssert recovered.len == blob_count
      for row in 0 ..< blob_count:
        let cp = computeCellsAndKzgProofs(blobs[row]).valueOr:
          raiseAssert "computeCellsAndKzgProofs failed"
        for columnIndex in 0 ..< kzg_abi.CELLS_PER_EXT_BLOB:
          doAssert recovered[row].cells[columnIndex].bytes ==
            cp.cells[columnIndex].bytes
          doAssert recovered[row].proofs[columnIndex].bytes ==
            cp.proofs[columnIndex].bytes
    testRecoverParallelValid()

  test "KZG: Recover Cells And Kzg Proofs Parallel - invalid":
    proc testRecoverParallelInvalid() =
      var rng = initRand(126)
      let
        blobs = createSampleKzgBlobs(2, rng.rand(int))
        built = buildSidecarsFromBlobs(blobs)

      # Fewer than half the columns cannot be recovered from
      var tooFew = newSeq[ref gloas.DataColumnSidecar]()
      for columnIndex in countup(0, (kzg_abi.CELLS_PER_EXT_BLOB div 2) - 2, 2):
        tooFew.add((ref gloas.DataColumnSidecar)(
          index: ColumnIndex(columnIndex),
          column: built.gloasSidecars[columnIndex].column))

      var tp =
        try: Taskpool.new()
        except CatchableError as exc: raiseAssert exc.msg
      defer: tp.shutdown()
      doAssert (waitFor tp.recover_cells_and_proofs_parallel(tooFew)).isErr
    testRecoverParallelInvalid()

doAssert freeTrustedSetup().isOk
