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

export
  BestSyncSubcommitteeContributions,
  Slot,
  SyncCommitteeContribution,
  SyncCommitteeIndex,
  SyncCommitteeMsgPool,
  SyncAggregate,
  TrustedSyncCommitteeMsg

const
  syncCommitteeMsgsRetentionSlots = 3
    ## How many slots to retain sync committee
    ## messsages before discarding them.

func init*(T: type SyncCommitteeMsgPool,
           onSyncContribution: OnSyncContributionCallback = nil
          ): SyncCommitteeMsgPool =
  T(onContributionReceived: onSyncContribution)

func init(T: type SyncAggregate): SyncAggregate =
  SyncAggregate(sync_committee_signature: ValidatorSig.infinity)

func pruneData*(pool: var SyncCommitteeMsgPool, slot: Slot) =
  ## This should be called at the end of slot.
  clear pool.seenContributionByAuthor
  clear pool.seenSyncMsgByAuthor

  if slot < syncCommitteeMsgsRetentionSlots:
    return

  let minSlotToRetain = slot - syncCommitteeMsgsRetentionSlots
  var syncMsgsToDelete: seq[Eth2Digest]
  var contributionsToDelete: seq[Eth2Digest]

  for blockRoot, msgs in pool.syncMessages:
    if msgs[0].slot < minSlotToRetain:
      syncMsgsToDelete.add blockRoot

  for blockRoot in syncMsgsToDelete:
    pool.syncMessages.del blockRoot

  for blockRoot, bestContributions in pool.bestContributions:
    if bestContributions.slot < minSlotToRetain:
      contributionsToDelete.add blockRoot

  for blockRoot in contributionsToDelete:
    pool.bestContributions.del blockRoot

func addSyncCommitteeMsg*(
    pool: var SyncCommitteeMsgPool,
    slot: Slot,
    blockRoot: Eth2Digest,
    signature: CookedSig,
    committeeIdx: SyncCommitteeIndex,
    positionInCommittee: uint64) =
  pool.syncMessages.mgetOrPut(blockRoot, @[]).add TrustedSyncCommitteeMsg(
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
    headRoot: Eth2Digest,
    committeeIdx: SyncCommitteeIndex,
    outContribution: var SyncCommitteeContribution): bool =
  if headRoot in pool.syncMessages:
    outContribution.slot = slot
    outContribution.beacon_block_root = headRoot
    outContribution.subcommittee_index = committeeIdx.asUInt64
    try:
      return computeAggregateSig(pool.syncMessages[headRoot],
                                 committeeIdx,
                                 outContribution)
    except KeyError:
      raiseAssert "We have checked for the key upfront"
  else:
    return false

func addAggregateAux(bestVotes: var BestSyncSubcommitteeContributions,
                     contribution: SyncCommitteeContribution) =
  let
    currentBestTotalParticipants =
      bestVotes.subnets[contribution.subcommittee_index].totalParticipants
    newBestTotalParticipants = countOnes(contribution.aggregation_bits)

  if newBestTotalParticipants > currentBestTotalParticipants:
    bestVotes.subnets[contribution.subcommittee_index] =
      BestSyncSubcommitteeContribution(
        totalParticipants: newBestTotalParticipants,
        participationBits: contribution.aggregation_bits,
        signature: contribution.signature.load.get)

proc addSyncContribution*(
    pool: var SyncCommitteeMsgPool,
    scproof: SignedContributionAndProof,
    signature: CookedSig) =

  template blockRoot: auto =
    scproof.message.contribution.beacon_block_root
  template subcommitteeIndex: auto =
    scproof.message.contribution.subcommittee_index
  template aggregationBits: auto =
    scproof.message.contribution.aggregation_bits

  if blockRoot notin pool.bestContributions:
    let totalParticipants = countOnes(aggregationBits)
    var initialBestContributions = BestSyncSubcommitteeContributions(
      slot: scproof.message.contribution.slot)

    initialBestContributions.subnets[subcommitteeIndex] =
      BestSyncSubcommitteeContribution(
        totalParticipants: totalParticipants,
        participationBits: aggregationBits,
        signature: signature)

    pool.bestContributions[blockRoot] = initialBestContributions
  else:
    try:
      addAggregateAux(pool.bestContributions[blockRoot],
                      scproof.message.contribution)
    except KeyError:
      raiseAssert "We have checked for the key upfront"

  if not(isNil(pool.onContributionReceived)):
    pool.onContributionReceived(scproof)

proc produceSyncAggregateAux(
    bestContributions: BestSyncSubcommitteeContributions): SyncAggregate =
  var
    aggregateSig {.noInit.}: AggregateSignature
    initialized = false
    startTime = Moment.now

  for subnetId in 0 ..< SYNC_COMMITTEE_SUBNET_COUNT:
    if bestContributions.subnets[subnetId].totalParticipants == 0:
      continue

    for pos, value in bestContributions.subnets[subnetId].participationBits:
      if value:
        let globalPos = subnetId * SYNC_SUBCOMMITTEE_SIZE + pos
        result.sync_committee_bits.setBit globalPos

    if not initialized:
      initialized = true
      aggregateSig.init(bestContributions.subnets[subnetId].signature)
    else:
      aggregateSig.aggregate(bestContributions.subnets[subnetId].signature)

  if initialized:
    result.sync_committee_signature = aggregateSig.finish.toValidatorSig
  else:
    result.sync_committee_signature = ValidatorSig.infinity

  let duration = Moment.now - startTime
  debug "SyncAggregate produced", duration,
         bits = result.sync_committee_bits

proc produceSyncAggregate*(
    pool: SyncCommitteeMsgPool,
    targetRoot: Eth2Digest): SyncAggregate =
  if targetRoot in pool.bestContributions:
    try:
      produceSyncAggregateAux(pool.bestContributions[targetRoot])
    except KeyError:
      raiseAssert "We have checked for the key upfront"
  else:
    SyncAggregate.init()
