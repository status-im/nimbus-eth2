# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/json,
  yaml,
  kzg4844/kzg_ex,
  stew/[byteutils, results],
  ../testutil,
  ./fixtures_utils, ./os_ops

from std/sequtils import anyIt, mapIt, toSeq
from std/strutils import rsplit

func fromHex[N: static int](s: string): Opt[array[N, byte]] =
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
  test "KZG - Blob to KZG commitment - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/formats/kzg/blob_to_kzg_commitment.md#condition
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
  test "KZG - Verify KZG proof - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      commitment = fromHex[48](data["input"]["commitment"].getStr)
      z = fromHex[32](data["input"]["z"].getStr)
      y = fromHex[32](data["input"]["y"].getStr)
      proof = fromHex[48](data["input"]["proof"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/formats/kzg/verify_kzg_proof.md#condition
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
  test "KZG - Verify blob KZG proof - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)
      commitment = fromHex[48](data["input"]["commitment"].getStr)
      proof = fromHex[48](data["input"]["proof"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/formats/kzg/verify_blob_kzg_proof.md#condition
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
  test "KZG - Verify blob KZG proof batch - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blobs = data["input"]["blobs"].mapIt(fromHex[131072](it.getStr))
      commitments = data["input"]["commitments"].mapIt(fromHex[48](it.getStr))
      proofs = data["input"]["proofs"].mapIt(fromHex[48](it.getStr))

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/formats/kzg/verify_blob_kzg_proof_batch.md#condition
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
  test "KZG - Compute KZG proof - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)
      z = fromHex[32](data["input"]["z"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/formats/kzg/compute_kzg_proof.md#condition
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
  test "KZG - Compute blob KZG proof - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex[131072](data["input"]["blob"].getStr)
      commitment = fromHex[48](data["input"]["commitment"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/formats/kzg/compute_blob_kzg_proof.md#condition
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
      # TODO Trying to access value with err Result [ResultDefect]
      if path == "blob_to_kzg_commitment_case_invalid_blob_59d64ff6b4648fad":
        continue
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
      # TODO in both cases, it's not properly detecting invalid input and
      # creating an actual proof/y pair instead of an error
      if path in [
          "compute_kzg_proof_case_invalid_blob_59d64ff6b4648fad",
          "compute_kzg_proof_case_invalid_z_b30d81e81c1262b6"]:
        continue
      runComputeKzgProofTest(suiteName, testsDir, testsDir / path)

  block:
    let testsDir = suitePath/"compute_blob_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      # TODO in one case the same case as before, and maybe the invalid
      # commitment too
      if path in [
          "compute_blob_kzg_proof_case_invalid_blob_59d64ff6b4648fad",
          "compute_blob_kzg_proof_case_invalid_commitment_d070689c3e15444c"]:
        continue
      runComputeBlobKzgProofTest(suiteName, testsDir, testsDir / path)

doAssert Kzg.freeTrustedSetup().isOk
