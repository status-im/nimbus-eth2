# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/strutils
import ssz_serialization/[types, bitseqs]
import stew/endians2
import nimcrypto/hash
import "."/common

{.push raises: [].}

type
  CommitteeBitsArray = BitArray[int(MAX_VALIDATORS_PER_COMMITTEE)]
  CommitteeTable = Table[CommitteeIndex, CommitteeBitsArray]

const
  DefaultCommitteeTable = default(CommitteeTable)
  DefaultCommitteeBitsArray = default(CommitteeBitsArray)

func perfectScore*(score: float64): bool =
  score == Inf

proc shortScore*(score: float64): string =
  if score == Inf:
    "<perfect>"
  elif score == -Inf:
    "<bad>"
  else:
    formatFloat(score, ffDecimal, 4)

func getLexicographicScore(digest: Eth2Digest): float64 =
  # We calculate score on first 8 bytes of digest.
  let
    dvalue = uint64.fromBytesBE(digest.data.toOpenArray(0, sizeof(uint64) - 1))
    value = float64(dvalue) / float64(high(uint64))
  value

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

proc getAggregatedAttestationDataScore*(
       adata: GetAggregatedAttestationResponse
     ): float64 =
  # This procedure returns score value in range [0.0000, 1.0000) and `Inf`.
  # It returns perfect score when all the bits was set to `1`, but this could
  # provide wrong expectation for some edge cases (when different attestations
  # has different committee sizes), but currently this is the only viable way
  # to return perfect score.
  const MaxLength = int(MAX_VALIDATORS_PER_COMMITTEE)
  doAssert(len(adata.data.aggregation_bits) <= MaxLength)
  let
    size = len(adata.data.aggregation_bits)
    ones = countOnes(adata.data.aggregation_bits)
    res =
      if ones == size:
        # We consider score perfect, when all bits was set to 1.
        Inf
      else:
        float64(ones) / float64(size)

  debug "Aggregated attestation score", attestation_data = shortLog(adata.data),
        block_slot = adata.data.data.slot, committee_size = size,
        ones_count = ones, score = shortScore(res)
  res

proc getSyncCommitteeContributionDataScore*(
       cdata: ProduceSyncCommitteeContributionResponse
     ): float64 =
  # This procedure returns score value in range [0.0000, 1.0000) and `Inf`.
  # It returns perfect score when all the bits was set to `1`, but this could
  # provide wrong expectation for some edge cases (when different contributions
  # has different committee sizes), but currently this is the only viable way
  # to return perfect score.
  const MaxLength = int(SYNC_SUBCOMMITTEE_SIZE)
  doAssert(len(cdata.data.aggregation_bits) <= MaxLength)
  let
    size = len(cdata.data.aggregation_bits)
    ones = countOnes(cdata.data.aggregation_bits)
    res =
      if ones == size:
        # We consider score perfect, when all bits was set to 1.
        Inf
      else:
        float64(ones) / float64(size)

  debug "Sync committee contribution score",
        contribution_data = shortLog(cdata.data), block_slot = cdata.data.slot,
        committee_size = size, ones_count = ones, score = shortScore(res)
  res

proc getSyncCommitteeMessageDataScore*(
       rootsSeen: Table[Eth2Digest, Slot],
       currentSlot: Slot,
       cdata: GetBlockRootResponse
     ): float64 =
  let
    slot = rootsSeen.getOrDefault(cdata.data.root, FAR_FUTURE_SLOT)
    res =
      if cdata.execution_optimistic.get(true):
        # Responses from the nodes which are optimistically synced only are
        # not suitable, score it with minimal possible score.
        -Inf
      else:
        if slot != FAR_FUTURE_SLOT:
          # When `slot` has been found score value will be in range of
          # `(1, 2]` or `Inf`.
          if slot == currentSlot:
            # Perfect score
            Inf
          else:
            float64(1) +
              float64(1) / (float64(1) + float64(currentSlot) - float64(slot))
        else:
          # Block monitoring is disabled or we missed a block, in this case
          # score value will be in range of `(0, 1]`
          getLexicographicScore(cdata.data.root)

  debug "Sync committee message score",
        head_block_root = shortLog(cdata.data.root), slot = slot,
        current_slot = currentSlot, score = shortScore(res)
  res

proc getSyncCommitteeMessageDataScore*(
       vc: ValidatorClientRef,
       cdata: GetBlockRootResponse
     ): float64 =
  getSyncCommitteeMessageDataScore(
    vc.rootsSeen, vc.beaconClock.now().slotOrZero(), cdata)

proc processVotes(bits: var CommitteeBitsArray,
                  attestation: Attestation): int =
  doAssert(len(attestation.aggregation_bits) <= len(bits))
  var res = 0
  for index in 0 ..< len(attestation.aggregation_bits):
    if attestation.aggregation_bits[index]:
      if not(bits[index]):
        inc(res)
        bits[index] = true
  res

proc getUniqueVotes*(attestations: openArray[Attestation]): int =
  var
    res = 0
    attested: Table[Slot, CommitteeTable]
  for attestation in attestations:
    let count =
      attested.mgetOrPut(attestation.data.slot, DefaultCommitteeTable).
        mgetOrPut(CommitteeIndex(attestation.data.index),
                  DefaultCommitteeBitsArray).
          processVotes(attestation)
    res += count
  res
