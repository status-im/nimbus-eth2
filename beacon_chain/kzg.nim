# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/os,
  stew/results,
  kzg4844/kzg_ex,
  ../../../vendor/nimpeerdaskzg/nim_peerdas_kzg/nim_peerdas_kzg


from std/strutils import rsplit

var ctx: nim_peerdas_kzg.KZGCtx

proc initKZG*(): bool =
  # TODO: no compilation flag here because c-kzg does more than peerdas functionality.   
  ctx = newKZGCtx()
  template sourceDir: string = currentSourcePath.rsplit(DirSep, 1)[0]
  return Kzg.loadTrustedSetup(
    sourceDir &
      "/../vendor/nim-kzg4844/kzg4844/csources/src/trusted_setup.txt").isOk

proc freeKZG*(): Result[void, string] =
  # TODO: add code to free nim_peerdas_kzg. Removed due to nim not allowing
  # TODO; the particular destory function being called.
  Kzg.freeTrustedSetup()

proc blobToKZGCommitment*(blob : array[131_072, byte]): Result[array[48, byte], string] =
  when defined(USE_NIMPEERDAS_KZG):
    let commitment = ?ctx.blobToKzgCommitment(Blob(bytes: blob))
    ok(commitment.bytes)
  else:
    kzg_ex.blobToKZGCommitment(blob)
