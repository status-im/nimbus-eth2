# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/strutils
import "."/common

{.push raises: [].}

func perfectScore*(score: float64): bool =
  score == Inf

proc shortScore*(score: float64): string =
  if score == Inf: "<perfect>" else: formatFloat(score, ffDecimal, 4)

proc getAttestationDataScore*(rootsSeen: Table[Eth2Digest, Slot],
                              adata: ProduceAttestationDataResponse): float64 =
  let
    slot = rootsSeen.getOrDefault(
      adata.data.beacon_block_root, FAR_FUTURE_SLOT)

  let res =
    if (slot == adata.data.slot) and
       (adata.data.source.epoch + 1 == adata.data.target.epoch):
      # Perfect score
      Inf
    else:
      let score = float64(adata.data.source.epoch) +
                  float64(adata.data.target.epoch)
      if slot == FAR_FUTURE_SLOT:
        score
      else:
        if adata.data.slot + 1 == slot:
          # To avoid `DivizionByZero` defect.
          score
        else:
          score + float64(1) / (float64(adata.data.slot) + float64(1) -
                                float64(slot))

  debug "Attestation score", attestation_data = shortLog(adata.data),
        block_slot = slot, score = shortScore(res)
  res

proc getAttestationDataScore*(vc: ValidatorClientRef,
                              adata: ProduceAttestationDataResponse): float64 =
  getAttestationDataScore(vc.rootsSeen, adata)
