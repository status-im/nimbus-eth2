# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/json,
  yaml,
  kzg4844/kzg_ex,
  stint,
  stew/[byteutils, results],
  ../testutil,
  ./fixtures_utils, ./os_ops

from std/sequtils import anyIt, mapIt, toSeq
from std/strutils import rsplit

func toUInt64(s: int): Opt[uint64] =
  if s < 0:
    return Opt.none uint64
  try:
    Opt.some uint64(s)
  except ValueError:
    Opt.none uint64

func fromHex[N: static int](s: string): Opt[array[N, byte]] =
  if s.len != 2*(N+1):
    # 0x prefix
    return Opt.none array[N, byte]

  try:
    Opt.some fromHex(array[N, byte], s)
  except ValueError:
    Opt.none array[N, byte]

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert Kzg.loadTrustedSetup(
    sourceDir &
      "/../../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt").isOk

proc runBlobToKzgCommitmentTest(suiteName, suitePath, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath)
  test "KZG - Blob to KZG commitment - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/tests/formats/kzg/blob_to_kzg_commitment.md#condition
    # If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) it should error, i.e. the
    # output should be `null`.
    if blob.isNone:
      check output.kind == JNull
    else:
      let commitment = blobToKzgCommitment(blob.get)
      check:
        if commitment.isErr:
          output.kind == JNull
        else:
          commitment.get == fromHex[48](output.getStr).get

proc runVerifyKzgProofTest(suiteName, suitePath, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath)
  test "KZG - Verify KZG proof - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      commitment = fromHex[48](data["input"]["commitment"].getStr)
      z = fromHex[32](data["input"]["z"].getStr)
      y = fromHex[32](data["input"]["y"].getStr)
      proof = fromHex[48](data["input"]["proof"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/tests/formats/kzg/verify_kzg_proof.md#condition
    # "If the commitment or proof is invalid (e.g. not on the curve or not in
    # the G1 subgroup of the BLS curve) or `z` or `y` are not a valid BLS
    # field element, it should error, i.e. the output should be `null`."
    if commitment.isNone or z.isNone or y.isNone or proof.isNone:
      check output.kind == JNull
    else:
      let v = verifyProof(commitment.get, z.get, y.get, proof.get)
      check:
        if v.isErr:
          output.kind == JNull
        else:
          v.get == output.getBool

proc runVerifyBlobKzgProofTest(suiteName, suitePath, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath)
  test "KZG - Verify blob KZG proof - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)
      commitment = fromHex[48](data["input"]["commitment"].getStr)
      proof = fromHex[48](data["input"]["proof"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/tests/formats/kzg/verify_blob_kzg_proof.md#condition
    # "If the commitment or proof is invalid (e.g. not on the curve or not in
    # the G1 subgroup of the BLS curve) or `blob` is invalid (e.g. incorrect
    # length or one of the 32-byte blocks does not represent a BLS field
    # element), it should error, i.e. the output should be `null`."
    if blob.isNone or commitment.isNone or proof.isNone:
      check output.kind == JNull
    else:
      let v = verifyBlobKzgProof(blob.get, commitment.get, proof.get)
      check:
        if v.isErr:
          output.kind == JNull
        else:
          v.get == output.getBool

proc runVerifyBlobKzgProofBatchTest(suiteName, suitePath, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath)
  test "KZG - Verify blob KZG proof batch - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blobs = data["input"]["blobs"].mapIt(fromHex[131072](it.getStr))
      commitments = data["input"]["commitments"].mapIt(fromHex[48](it.getStr))
      proofs = data["input"]["proofs"].mapIt(fromHex[48](it.getStr))

    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/tests/formats/kzg/verify_blob_kzg_proof_batch.md#condition
    # "If any of the commitments or proofs are invalid (e.g. not on the curve or
    # not in the G1 subgroup of the BLS curve) or any blob is invalid (e.g.
    # incorrect length or one of the 32-byte blocks does not represent a BLS
    # field element), it should error, i.e. the output should be null."
    if  blobs.anyIt(it.isNone) or commitments.anyIt(it.isNone) or
        proofs.anyIt(it.isNone):
      check output.kind == JNull
    else:
      let v = verifyBlobKzgProofBatch(
        blobs.mapIt(it.get), commitments.mapIt(it.get), proofs.mapIt(it.get))
      check:
        if v.isErr:
          output.kind == JNull
        else:
          v.get == output.getBool

proc runComputeKzgProofTest(suiteName, suitePath, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath)
  test "KZG - Compute KZG proof - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)
      z = fromHex[32](data["input"]["z"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.0/tests/formats/kzg/compute_kzg_proof.md#condition
    # "If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) or z is not a valid BLS
    # field element, it should error, i.e. the output should be null."
    if blob.isNone or z.isNone:
      check output.kind == JNull
    else:
      let p = computeKzgProof(blob.get, z.get)
      if p.isErr:
        check output.kind == JNull
      else:
        let
          proof = fromHex[48](output[0].getStr)
          y = fromHex[32](output[1].getStr)
        check:
          p.get.proof == proof.get
          p.get.y == y.get

proc runComputeBlobKzgProofTest(suiteName, suitePath, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath)
  test "KZG - Compute blob KZG proof - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)
      commitment = fromHex[48](data["input"]["commitment"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.6/tests/formats/kzg/compute_blob_kzg_proof.md#condition
    # If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) it should error, i.e. the
    # output should be `null`.
    if blob.isNone or commitment.isNone:
      check output.kind == JNull
    else:
      let p = computeBlobKzgProof(blob.get, commitment.get)
      if p.isErr:
        check output.kind == JNull
      else:
        check p.get == fromHex[48](output.getStr).get

proc runComputeCellsTest(suiteName2, suitePath2, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath2)
  test "KZG - Compute Cells - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)
    
    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.2/tests/formats/kzg_7594/verify_cell_kzg_proof.md#condition
    # If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) it should error, i.e. the
    # the output should be `null`.
    if blob.isNone:
      check output.kind == JNull
    else:
      let p = computeCells(blob.get)
      if p.isErr:
        check output.kind == JNull
      else:
        for i in 0..<128:
          check p.get[i] == fromHex[2048](output.getStr).get

proc runComputeCellsAndProofsTest(suiteName2, suitePath2, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath2)
  test "KZG - Compute Cells And Proofs - " & relativePathComponent:
    let 
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.2/tests/formats/kzg_7594/verify_cell_kzg_proof.md#condition
    # If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) it should error, i.e. the
    # the output should be `null`.
    if blob.isNone:
      check output.kind == JNull
    else:
      let p = computeCellsAndProofs(blob.get)
      if p.isErr:
        check output.kind == JNull
      else:
        for i in 0..<128:
          check p.get.cells[i] == fromHex[2048](output["cells"].getStr).get
          check p.get.proofs[i] == fromHex[48](output["proofs"].getStr).get

proc runVerifyCellKzgProofsTest(suiteName2, suitePath2, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath2)
  test "KZG - Verify Cell Kzg Proof - " & relativePathComponent:
    let 
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      commitment = fromHex[48](data["input"]["commitment"].getStr)
      proof = fromHex[48](data["input"]["proof"].getStr)
      cell = fromHex[2048](data["input"]["cell"].getStr)
      cell_id = toUInt64(data["input"]["cell_id"].getInt)
    
    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.2/tests/formats/kzg_7594/verify_cell_kzg_proof.md#condition
    # If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) it should error, i.e. the
    # the output should be `null`.
    if commitment.isNone or proof.isNone or cell.isNone or cell_id.isNone:
      check output.kind == JNull
    else:
      let p = verifyCellKzgProof(commitment.get, cell_id.get, cell.get, proof.get)
      if p.isErr:
        check output.kind == JNull
      else:
        check p.get == output.getBool

proc runVerifyCellKzgProofBatchTest(suiteName2, suitePath2, path: string) =
  let relativePathCompnent = path.relativeTestPathComponent(suitePath2)
  test "KZG - Verify Cell Kzg Proof Batch - " & relativePathCompnent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      row_commitments = data["input"]["row_commitments"].mapIt(fromHex[48](it.getStr))
      row_indices = data["input"]["row_indices"].mapIt(toUInt64(it.getInt))
      column_indices = data["input"]["column_indices"].mapIt(toUInt64(it.getInt))
      cells = data["input"]["cells"].mapIt(fromHex[2048](it.getStr))
      proofs = data["input"]["proofs"].mapIt(fromHex[48](it.getStr))

    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.2/tests/formats/kzg_7594/verify_cell_kzg_proof_batch.md#condition
    # If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) it should error, i.e. the
    # the output should be `null`.
    if row_commitments.anyIt(it.isNone) or row_indices.anyIt(it.isNone) or
        column_indices.anyIt(it.isNone) or proofs.anyIt(it.isNone) or
        cells.anyIt(it.isNone):
      check output.kind == JNull
    else:
      let v = verifyCellKzgProofBatch(
            row_commitments.mapIt(it.get),
            row_indices.mapIt(it.get),
            column_indices.mapIt(it.get),
            cells.mapIt(it.get),
            proofs.mapIt(it.get)
          )
      check:
        if v.isErr:
          output.kind == JNull
        else:
          v.get == output.getBool

proc runRecoverAllCellsTest(suiteName2, suitePath2, path: string) =
  let relativePathComponent = path.relativeTestPathComponent(suitePath2)
  test "KZG - Recover All Cells - " & relativePathComponent:
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      cell_ids = data["input"]["cell_ids"].mapIt(toUInt64(it.getInt))
      cells = data["input"]["cells"].mapIt(fromHex[2048](it.getStr))

    # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.2/tests/formats/kzg_7594/recover_all_cells.md#condition
    # If the blob is invalid (e.g. incorrect length or one of the 32-byte
    # blocks does not represent a BLS field element) it should error, i.e. the
    # the output should be `null`.
    if cell_ids.anyIt(it.isNone) or cells.anyIt(it.isNone):
      check output.kind == JNull
    else:
      let v = recoverAllCells(cell_ids.mapIt(it.get), cells.mapIt(it.get))
      if v.isErr:
        check output.kind == JNull
      else:
        for i in 0..<128:
          check v.get[i] == fromHex[2048](output.getStr).get

from std/algorithm import sorted

const suiteName = "EF - KZG"

suite suiteName:
  const suitePath = SszTestsDir/"general"/"deneb"/"kzg"

  # TODO also check that the only direct subdirectory of each is kzg-mainnet
  doAssert sorted(mapIt(
      toSeq(walkDir(suitePath, relative = true, checkDir = true)), it.path)) ==
    ["blob_to_kzg_commitment", "compute_blob_kzg_proof", "compute_kzg_proof",
     "verify_blob_kzg_proof", "verify_blob_kzg_proof_batch",
     "verify_kzg_proof"]

  block:
    let testsDir = suitePath/"blob_to_kzg_commitment"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runBlobToKzgCommitmentTest(suiteName, testsDir, testsDir/path)

  block:
    let testsDir = suitePath/"verify_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runVerifyKzgProofTest(suiteName, testsDir, testsDir/path)

  block:
    let testsDir = suitePath/"verify_blob_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runVerifyBlobKzgProofTest(suiteName, testsDir, testsDir/path)

  block:
    let testsDir = suitePath/"verify_blob_kzg_proof_batch"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runVerifyBlobKzgProofBatchTest(suiteName, testsDir, testsDir/path)

  block:
    let testsDir = suitePath/"compute_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runComputeKzgProofTest(suiteName, testsDir, testsDir / path)

  block:
    let testsDir = suitePath/"compute_blob_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runComputeBlobKzgProofTest(suiteName, testsDir, testsDir / path)

doAssert Kzg.freeTrustedSetup().isOk

const suiteName2 = "EF - KZG - EIP7594"

suite suiteName2:
  const suitePath2 = SszTestsDir/"general"/"eip7594"/"kzg"

  # TODO also check that the only direct subdirectory of each is kzg-mainnet
  doAssert sorted(mapIt(
      toSeq(walkDir(suitePath2, relative = true, checkDir = true)), it.path)) ==
    ["compute_cells", "compute_cells_and_kzg_proofs", "recover_all_cells",
     "verify_cell_kzg_proof", "verify_cell_kzg_proof_batch"]

  block:
    let testsDir = suitePath2/"compute_cells"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runComputeCellsTest(suiteName2, testsDir, testsDir/path)

  block:
    let testsDir = suitePath2/"compute_cells_and_kzg_proofs"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runComputeCellsAndProofsTest(suiteName2, testsDir, testsDir/path)

  block:
    let testsDir = suitePath2/"recover_all_cells"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runRecoverAllCellsTest(suiteName2, testsDir, testsDir/path)

  block:
    let testsDir = suitePath2/"verify_cell_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runVerifyCellKzgProofsTest(suiteName2, testsDir, testsDir/path)

  block:
    let testsDir = suitePath2/"verify_cell_kzg_proof_batch"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runVerifyCellKzgProofBatchTest(suiteName2, testsDir, testsDir/path)

doAssert Kzg.freeTrustedSetup().isOk