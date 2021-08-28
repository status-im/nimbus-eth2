# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/sets,
  chronicles,
  ../spec/digest,
  ../spec/datatypes/altair,
  ../beacon_node_types,
  ./block_pools_types

func init*(T: type SyncCommitteeMsgPool): SyncCommitteeMsgPool =
  discard

func init(T: type SyncAggregate): SyncAggregate =
  SyncAggregate(sync_committee_signature: ValidatorSig.infinity)

func clearPerSlotData*(pool: var SyncCommitteeMsgPool) =
  clear pool.seenAggregateByAuthor
  clear pool.seenByAuthor
  # TODO The previously implemened pruning has proven to be too
  # aggressive. We can consider a scheme where the data is pruned
  # with several slots of delay to allow for late sync committee
  # messages.
  # clear pool.bestAggregates
  # clear pool.blockVotes

func addSyncCommitteeMsg*(
    pool: var SyncCommitteeMsgPool,
    slot: Slot,
    beaconBlockRoot: Eth2Digest,
    signature: CookedSig,
    committeeIdx: SyncCommitteeIndex,
    positionInCommittee: uint64) =
  pool.blockVotes.mgetOrPut(beaconBlockRoot, @[]).add TrustedSyncCommitteeMsg(
    slot: slot,
    committeeIdx: committeeIdx,
    positionInCommittee: positionInCommittee,
    signature: signature)

func computeAggregateSig(votes: seq[TrustedSyncCommitteeMsg],
                         committeeIdx: SyncCommitteeIndex,
                         contribution: var SyncCommitteeContribution): bool =
  var
    aggregateSig {.noInit.}: AggregateSignature
    initialized = false

  for vote in votes:
    if vote.committeeIdx != committeeIdx:
      continue

    if not initialized:
      initialized = true
      aggregateSig.init(vote.signature)
    else:
      aggregateSig.aggregate(vote.signature)

    contribution.aggregation_bits.setBit vote.positionInCommittee

  if initialized:
    contribution.signature = aggregateSig.finish.toValidatorSig

  return initialized

func produceContribution*(
    pool: SyncCommitteeMsgPool,
    slot: Slot,
    head: BlockRef,
    committeeIdx: SyncCommitteeIndex,
    outContribution: var SyncCommitteeContribution): bool =
  if head.root in pool.blockVotes:
    outContribution.slot = slot
    outContribution.beacon_block_root = head.root
    outContribution.subcommittee_index = committeeIdx.asUInt64
    try:
      return computeAggregateSig(pool.blockVotes[head.root],
                                 committeeIdx,
                                 outContribution)
    except KeyError:
      raiseAssert "We have checked for the key upfront"
  else:
    return false

func addAggregateAux(bestVotes: var BestSyncSubcommitteeContributions,
                     contribution: SyncCommitteeContribution) =
  let totalParticipants = countOnes(contribution.aggregation_bits)
  if totalParticipants > bestVotes[contribution.subcommittee_index].totalParticipants:
    bestVotes[contribution.subcommittee_index] =
      BestSyncSubcommitteeContribution(
        totalParticipants: totalParticipants,
        participationBits: contribution.aggregation_bits,
        signature: contribution.signature.load.get)

func addSyncContribution*(
    pool: var SyncCommitteeMsgPool,
    contribution: SyncCommitteeContribution,
    signature: CookedSig) =

  template blockRoot: auto = contribution.beacon_block_root

  if blockRoot notin pool.bestAggregates:
    var bestContributions: BestSyncSubcommitteeContributions

    let totalParticipants = countOnes(contribution.aggregation_bits)

    bestContributions[contribution.subcommittee_index] =
      BestSyncSubcommitteeContribution(
        totalParticipants: totalParticipants,
        participationBits: contribution.aggregation_bits,
        signature: signature)

    pool.bestAggregates[blockRoot] = bestContributions
  else:
    try:
      addAggregateAux(pool.bestAggregates[blockRoot], contribution)
    except KeyError:
      raiseAssert "We have checked for the key upfront"

proc produceSyncAggregateAux(votes: BestSyncSubcommitteeContributions): SyncAggregate =
  var
    aggregateSig {.noInit.}: AggregateSignature
    initialized = false
    startTime = Moment.now

  for subnetId in 0 ..< SYNC_COMMITTEE_SUBNET_COUNT:
    if votes[subnetId].totalParticipants == 0:
      continue

    for pos, value in votes[subnetId].participationBits:
      if value:
        let globalPos = subnetId * SYNC_SUBCOMMITTEE_SIZE + pos
        result.sync_committee_bits.setBit globalPos

    if not initialized:
      initialized = true
      aggregateSig.init(votes[subnetId].signature)
    else:
      aggregateSig.aggregate(votes[subnetId].signature)

  if initialized:
    result.sync_committee_signature = aggregateSig.finish.toValidatorSig
  else:
    result.sync_committee_signature = ValidatorSig.infinity

  let duration = Moment.now - startTime
  debug "SyncAggregate produced", duration,
         bits = result.sync_committee_bits

proc produceSyncAggregate*(
    pool: SyncCommitteeMsgPool,
    target: BlockRef): SyncAggregate =
  if target.root in pool.bestAggregates:
    try:
      produceSyncAggregateAux(pool.bestAggregates[target.root])
    except KeyError:
      raiseAssert "We have checked for the key upfront"
  else:
    SyncAggregate.init()
