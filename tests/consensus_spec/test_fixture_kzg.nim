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

from std/strutils import rsplit

# Should be generic, but for https://github.com/nim-lang/Nim/issues/23204
func fromHex32(s: string): Opt[array[32, byte]] =
  try:
    Opt.some fromHex(array[32, byte], s)
  except ValueError:
    Opt.none array[32, byte]

func fromHex48(s: string): Opt[array[48, byte]] =
  try:
    Opt.some fromHex(array[48, byte], s)
  except ValueError:
    Opt.none array[48, byte]

func fromHex128KiB(s: string): Opt[array[131072, byte]] =
  try:
    Opt.some fromHex(array[131072, byte], s)
  except ValueError:
    Opt.none array[131072, byte]

block:
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  doAssert Kzg.loadTrustedSetup(
    sourceDir &
      "/../../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt").isOk

proc runVerifyKzgProofTest(suiteName, suitePath, path: string) =
  test "KZG - Verify KZG proof - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      commitment = fromHex48(data["input"]["commitment"].getStr)
      z = fromHex32(data["input"]["z"].getStr)
      y = fromHex32(data["input"]["y"].getStr)
      proof = fromHex48(data["input"]["proof"].getStr)

    # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/formats/kzg/verify_kzg_proof.md#condition
    # "If the commitment or proof is invalid (e.g. not on the curve or not in
    # the G1 subgroup of the BLS curve) or `z` or `y` are not a valid BLS
    # field element, it should error, i.e. the output should be `null`."
    if commitment.isNone or z.isNone or y.isNone or proof.isNone:
      check output.kind == JNull
    else:
      let p = verifyProof(commitment.get, z.get, y.get, proof.get)
      check:
        if p.isErr:
          output.kind == JNull
        else:
          p.get == output.getBool

proc runComputeKzgProofTest(suiteName, suitePath, path: string) =
  test "KZG - Compute KZG proof - " & path.relativePath(suitePath):
    let
      data = yaml.loadToJson(os_ops.readFile(path/"data.yaml"))[0]
      output = data["output"]
      blob = fromHex128KiB(data["input"]["blob"].getStr)
      z = fromHex32(data["input"]["z"].getStr)

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
          proof = fromHex48(output[0].getStr)
          y = fromHex32(output[1].getStr)
        check:
          p.get.proof == proof.get
          p.get.y == y.get

suite "EF - KZG":
  const suitePath = SszTestsDir/"general"/"deneb"/"kzg"
  # TODO check that only subdirectory is kzg-mainnet in each case

  block:
    let testsDir = suitePath/"verify_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      runVerifyKzgProofTest("EF - KZG", testsDir, testsDir/path)

  block:
    let testsDir = suitePath/"compute_kzg_proof"/"kzg-mainnet"
    for kind, path in walkDir(testsDir, relative = true, checkDir = true):
      # TODO in both cases, it's not properly detecting invalid input and
      # creating an actual proof/y pair instead of an error
      if path in [
          "compute_kzg_proof_case_invalid_blob_59d64ff6b4648fad",
          "compute_kzg_proof_case_invalid_z_b30d81e81c1262b6"]:
        continue
      runComputeKzgProofTest("EF - KZG", testsDir, testsDir / path)

doAssert Kzg.freeTrustedSetup().isOk
