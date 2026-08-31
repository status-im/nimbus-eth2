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
  ../beacon_chain/spec/[helpers, network, peerdas_helpers],
  ../beacon_chain/spec/datatypes/[deneb, fulu, gloas]

from std/strutils import rsplit
from std/sequtils import mapIt

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

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.14/specs/gloas/partial-columns/p2p-interface.md
proc buildCommitmentsAndCellProofs(blobs: seq[KzgBlob]):
    tuple[commitments: gloas.KzgCommitments, cell_proofs: seq[Opt[KzgProof]]] =
  ## Cell proofs are laid out row-major, as the assembly helpers expect.
  var
    commitments = newSeqOfCap[KzgCommitment](blobs.len)
    cell_proofs =
      newSeqOfCap[Opt[KzgProof]](blobs.len * kzg_abi.CELLS_PER_EXT_BLOB)
  for blob in blobs:
    let cp = computeCellsAndKzgProofs(blob).valueOr:
      raiseAssert "computeCellsAndKzgProofs failed"
    for columnIndex in 0 ..< kzg_abi.CELLS_PER_EXT_BLOB:
      cell_proofs.add(Opt.some(cp.proofs[columnIndex]))
    let commitment = blobToKzgCommitment(blob).valueOr:
      raiseAssert "blobToKzgCommitment failed"
    commitments.add(commitment)
  (commitments, cell_proofs)

func gloasBlockWithCommitments(
    commitments: gloas.KzgCommitments, slot: Slot): gloas.SignedBeaconBlock =
  var blck: gloas.SignedBeaconBlock
  blck.message.slot = slot
  blck.message.body.signed_execution_payload_bid.message.blob_kzg_commitments =
    commitments
  blck

suite "Gloas Partial Columns":
  test "Assemble partial data column sidecars":
    proc testAssemble() =
      var rng = initRand(45)
      let
        blobCount = rng.rand(1..4)
        blobs = createSampleKzgBlobs(blobCount, rng.rand(int))
        (commitments, cellProofs) = buildCommitmentsAndCellProofs(blobs)
        blck = gloasBlockWithCommitments(commitments, Slot(37))
        (groupId, sidecars) = assemble_partial_data_column_sidecars(
          blck, blobs.mapIt(Opt.some(it)), cellProofs)

      # The group id binds the sidecars to the block, in place of Fulu's
      # PartialDataColumnHeader.
      doAssert groupId.slot == Slot(37)
      doAssert groupId.beacon_block_root == blck.root

      doAssert sidecars.len == kzg_abi.CELLS_PER_EXT_BLOB
      for sidecar in sidecars:
        doAssert sidecar.cells_present_bitmap.len == blobCount
        doAssert sidecar.partial_column.len == blobCount
        doAssert sidecar.kzg_proofs.len == blobCount
        doAssert verify_partial_data_column_sidecar(sidecar).isOk

      # Verifying every column is needlessly slow; a few suffice.
      for columnIndex in [0, 1, kzg_abi.CELLS_PER_EXT_BLOB - 1]:
        doAssert verify_partial_data_column_sidecar_kzg_proofs(
          sidecars[columnIndex], commitments, ColumnIndex(columnIndex)).isOk
    testAssemble()

  test "Assemble partial data column sidecars with missing rows":
    proc testAssembleSparse() =
      var rng = initRand(46)
      let
        blobs = createSampleKzgBlobs(3, rng.rand(int))
        (commitments, cellProofs) = buildCommitmentsAndCellProofs(blobs)
        blck = gloasBlockWithCommitments(commitments, Slot(9))

      # Drop the middle blob; its bit must be clear in every column.
      var sparse = blobs.mapIt(Opt.some(it))
      sparse[1] = Opt.none(KzgBlob)

      let (_, sidecars) =
        assemble_partial_data_column_sidecars(blck, sparse, cellProofs)

      for sidecar in sidecars:
        doAssert sidecar.cells_present_bitmap.len == 3
        doAssert sidecar.cells_present_bitmap[0]
        doAssert not sidecar.cells_present_bitmap[1]
        doAssert sidecar.cells_present_bitmap[2]
        doAssert sidecar.partial_column.len == 2
        doAssert verify_partial_data_column_sidecar(sidecar).isOk

      doAssert verify_partial_data_column_sidecar_kzg_proofs(
        sidecars[0], commitments, ColumnIndex(0)).isOk
    testAssembleSparse()

  test "Assemble rejects mismatched blob and proof counts":
    proc testAssembleMismatch() =
      var rng = initRand(47)
      let
        blobs = createSampleKzgBlobs(2, rng.rand(int))
        (commitments, cellProofs) = buildCommitmentsAndCellProofs(blobs)
        blck = gloasBlockWithCommitments(commitments, Slot(1))
        optBlobs = blobs.mapIt(Opt.some(it))

      # Fewer cell proofs than blobs * CELLS_PER_EXT_BLOB
      block:
        let (_, sidecars) = assemble_partial_data_column_sidecars(
          blck, optBlobs, cellProofs[0 ..< cellProofs.len - 1])
        doAssert sidecars.len == 0

      # Blob count not matching the bid's commitments
      block:
        let (_, sidecars) = assemble_partial_data_column_sidecars(
          blck, optBlobs[0 ..< 1], cellProofs)
        doAssert sidecars.len == 0

      # No commitments in the bid at all
      block:
        let
          emptyBlck = gloasBlockWithCommitments(default(gloas.KzgCommitments),
                                                Slot(1))
          (_, sidecars) = assemble_partial_data_column_sidecars(
            emptyBlck, optBlobs, cellProofs)
        doAssert sidecars.len == 0
    testAssembleMismatch()

  test "Verify PartialDataColumnSidecar self-consistency":
    proc testStructural() =
      var rng = initRand(48)
      let
        blobs = createSampleKzgBlobs(3, rng.rand(int))
        (commitments, cellProofs) = buildCommitmentsAndCellProofs(blobs)
        blck = gloasBlockWithCommitments(commitments, Slot(5))
        (_, sidecars) = assemble_partial_data_column_sidecars(
          blck, blobs.mapIt(Opt.some(it)), cellProofs)
        sidecar = sidecars[0]

      doAssert verify_partial_data_column_sidecar(sidecar).isOk

      # Gloas has no header, so a sidecar with no cells conveys nothing.
      doAssert verify_partial_data_column_sidecar(
        default(gloas.PartialDataColumnSidecar)).isErr

      block:
        var empty = sidecar
        empty.cells_present_bitmap = gloas.CellsPresentBits.init(3)
        doAssert verify_partial_data_column_sidecar(empty).isErr

      block:
        var tooFewCells = sidecar
        tooFewCells.partial_column = sidecar.partial_column[0 ..< 2]
        doAssert verify_partial_data_column_sidecar(tooFewCells).isErr

      block:
        var tooFewProofs = sidecar
        tooFewProofs.kzg_proofs = sidecar.kzg_proofs[0 ..< 2]
        doAssert verify_partial_data_column_sidecar(tooFewProofs).isErr
    testStructural()

  test "Verify PartialDataColumnSidecar KZG proofs":
    proc testKzg() =
      var rng = initRand(49)
      let
        blobs = createSampleKzgBlobs(3, rng.rand(int))
        (commitments, cellProofs) = buildCommitmentsAndCellProofs(blobs)
        blck = gloasBlockWithCommitments(commitments, Slot(5))
        (_, sidecars) = assemble_partial_data_column_sidecars(
          blck, blobs.mapIt(Opt.some(it)), cellProofs)
        sidecar = sidecars[2]

      doAssert verify_partial_data_column_sidecar_kzg_proofs(
        sidecar, commitments, ColumnIndex(2)).isOk

      # Proofs are bound to the column index they were computed for.
      doAssert verify_partial_data_column_sidecar_kzg_proofs(
        sidecar, commitments, ColumnIndex(3)).isErr

      block:
        var corrupted = sidecar
        corrupted.kzg_proofs[0].bytes[0] =
          corrupted.kzg_proofs[0].bytes[0] xor 0xff'u8
        doAssert verify_partial_data_column_sidecar_kzg_proofs(
          corrupted, commitments, ColumnIndex(2)).isErr

      # A bitmap reaching past the commitments cannot be verified.
      block:
        let shortened =
          gloas.KzgCommitments(commitments.asSeq[0 ..< commitments.len - 1])
        doAssert verify_partial_data_column_sidecar_kzg_proofs(
          sidecar, shortened, ColumnIndex(2)).isErr
    testKzg()

  test "PartialDataColumnGroupID encoding":
    proc testGroupId() =
      var root: Eth2Digest
      root.data[0] = 7

      let groupId = gloas.PartialDataColumnGroupID(
        beacon_block_root: root, slot: Slot(4242))

      let encoded = encodePartialDataColumnGroupId(groupId)
      doAssert encoded.len == PARTIAL_DATA_COLUMN_GROUP_ID_LEN
      doAssert encoded[0] == PARTIAL_DATA_COLUMN_GROUP_ID_VERSION
      doAssert decodePartialDataColumnGroupId(encoded).get() == groupId

      block:
        var unknownVersion = encoded
        unknownVersion[0] = 0xff'u8
        doAssert decodePartialDataColumnGroupId(unknownVersion).isErr

      doAssert decodePartialDataColumnGroupId(
        encoded[0 ..< encoded.len - 1]).isErr
      doAssert decodePartialDataColumnGroupId(encoded & @[byte 0]).isErr
      doAssert decodePartialDataColumnGroupId([]).isErr
    testGroupId()

doAssert freeTrustedSetup().isOk
