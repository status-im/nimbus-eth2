# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/tables
import metrics
import ssz_serialization/types as sszTypes
import ./common
import ../spec/datatypes/[phase0, altair, bellatrix]
import ../spec/forks

{.push raises: [].}

type
  BitsTable = Table[uint64, BitArray[int(MAX_VALIDATORS_PER_COMMITTEE)]]

proc getAttestationDataScore*(vc: ValidatorClientRef,
                              adata: ProduceAttestationDataResponse): float64 =
  let
    slot = vc.rootsSeen.getOrDefault(
      adata.data.beacon_block_root, FAR_FUTURE_SLOT)
    score = float64(adata.data.source.epoch) + float64(adata.data.target.epoch)

  if slot == FAR_FUTURE_SLOT:
    score
  else:
    if adata.data.slot + 1 == slot:
      # To avoid `DivizionByZero` defect.
      score
    else:
      score + float64(1) / float64(adata.data.slot + 1 - slot)
