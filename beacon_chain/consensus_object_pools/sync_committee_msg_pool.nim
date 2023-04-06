# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sets, tables],
  stew/shims/hashes,
  eth/p2p/discoveryv5/random2,
  chronicles,
  ../spec/[crypto, digest],
  ../spec/datatypes/altair

export hashes, sets, tables, altair

const
  syncCommitteeMsgsRetentionSlots = 3
    ## How many slots to retain sync committee
    ## messsages before discarding them.

type
  SyncCommitteeMsgKey = object
    originator: uint64 # ValidatorIndex avoiding mess with invalid values
    slot: Slot
    subcommitteeIdx: uint64 # SyncSubcommitteeIndex avoiding mess with invalid values

  TrustedSyncCommitteeMsg* = object
    slot*: Slot
    subcommitteeIdx*: SyncSubcommitteeIndex
    positionInCommittee*: uint64
    signature*: CookedSig

  BestSyncSubcommitteeContribution* = object
    totalParticipants*: int
    participationBits*: SyncCommitteeAggregationBits
    signature*: CookedSig

  BestSyncSubcommitteeContributions* = object
    slot*: Slot
    subnets*: array[SYNC_COMMITTEE_SUBNET_COUNT,
                    BestSyncSubcommitteeContribution]

  OnSyncContributionCallback* =
    proc(data: SignedContributionAndProof) {.gcsafe, raises: [Defect].}

  SyncCommitteeMsgPool* = object
    seenSyncMsgByAuthor*: HashSet[SyncCommitteeMsgKey]
    seenContributionByAuthor*: HashSet[SyncCommitteeMsgKey]
    syncMessages*: Table[Eth2Digest, seq[TrustedSyncCommitteeMsg]]
    bestContributions*: Table[Eth2Digest, BestSyncSubcommitteeContributions]
    onContributionReceived*: OnSyncContributionCallback

    rng: ref HmacDrbgContext

func hash*(x: SyncCommitteeMsgKey): Hash =
  hashAllFields(x)

func init*(T: type SyncCommitteeMsgPool,
           rng: ref HmacDrbgContext,
           onSyncContribution: OnSyncContributionCallback = nil
          ): SyncCommitteeMsgPool =
  T(rng: rng, onContributionReceived: onSyncContribution)

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

func isSeen*(
    pool: SyncCommitteeMsgPool,
    msg: SyncCommitteeMessage,
    subcommitteeIdx: SyncSubcommitteeIndex): bool =
  let seenKey = SyncCommitteeMsgKey(
    originator: msg.validator_index, # Might be unvalidated at this point
    slot: msg.slot,
    subcommitteeIdx: subcommitteeIdx.uint64)
  seenKey in pool.seenSyncMsgByAuthor

proc addSyncCommitteeMessage*(
    pool: var SyncCommitteeMsgPool,
    slot: Slot,
    blockRoot: Eth2Digest,
    validatorIndex: uint64,
    signature: CookedSig,
    subcommitteeIdx: SyncSubcommitteeIndex,
    positionsInCommittee: openArray[uint64]) =

  let
    seenKey = SyncCommitteeMsgKey(
      originator: validatorIndex,
      slot: slot,
      subcommitteeIdx: subcommitteeIdx.uint64)

  pool.seenSyncMsgByAuthor.incl seenKey

  for position in positionsInCommittee:
    pool.syncMessages.mgetOrPut(blockRoot, @[]).add TrustedSyncCommitteeMsg(
      slot: slot,
      subcommitteeIdx: subcommitteeIdx,
      positionInCommittee: position,
      signature: signature)

  debug "Sync committee message resolved",
    slot = slot, blockRoot = shortLog(blockRoot), validatorIndex

func computeAggregateSig(votes: seq[TrustedSyncCommitteeMsg],
                         subcommitteeIdx: SyncSubcommitteeIndex,
                         contribution: var SyncCommitteeContribution): bool =
  var
    aggregateSig {.noinit.}: AggregateSignature
    initialized = false

  for vote in votes:
    if vote.subcommitteeIdx != subcommitteeIdx:
      continue

    if not contribution.aggregation_bits[vote.positionInCommittee]:
      if not initialized:
        initialized = true
        aggregateSig.init(vote.signature)
      else:
        aggregateSig.aggregate(vote.signature)

      contribution.aggregation_bits.setBit vote.positionInCommittee

  if initialized:
    contribution.signature = aggregateSig.finish.toValidatorSig

  initialized

func produceContribution*(
    pool: SyncCommitteeMsgPool,
    slot: Slot,
    headRoot: Eth2Digest,
    subcommitteeIdx: SyncSubcommitteeIndex,
    outContribution: var SyncCommitteeContribution): bool =
  if headRoot in pool.syncMessages:
    outContribution.slot = slot
    outContribution.beacon_block_root = headRoot
    outContribution.subcommittee_index = subcommitteeIdx.asUInt64
    try:
      computeAggregateSig(pool.syncMessages[headRoot],
                          subcommitteeIdx,
                          outContribution)
    except KeyError:
      raiseAssert "We have checked for the key upfront"
  else:
    false

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

func isSeen*(
    pool: SyncCommitteeMsgPool,
    msg: ContributionAndProof): bool =
  let seenKey = SyncCommitteeMsgKey(
    originator: msg.aggregator_index,
    slot: msg.contribution.slot,
    subcommitteeIdx: msg.contribution.subcommittee_index)
  seenKey in pool.seenContributionByAuthor

func covers(
    bestVotes: BestSyncSubcommitteeContributions,
    contribution: SyncCommitteeContribution): bool =
  contribution.aggregation_bits.isSubsetOf(
          bestVotes.subnets[contribution.subcommittee_index].participationBits)

func covers*(
    pool: var SyncCommitteeMsgPool,
    contribution: SyncCommitteeContribution): bool =
  ## Return true iff the given contribution brings no new information compared
  ## to the contributions already seen in the pool, ie if the contriubution is a
  ## subset of the best contribution so far
  pool.bestContributions.withValue(contribution.beacon_block_root, best):
    return best[].covers(contribution)

  return false

proc addContribution(pool: var SyncCommitteeMsgPool,
                     aggregator_index: uint64,
                     contribution: SyncCommitteeContribution,
                     signature: CookedSig) =
  let seenKey = SyncCommitteeMsgKey(
    originator: aggregator_index,
    slot: contribution.slot,
    subcommitteeIdx: contribution.subcommittee_index)
  pool.seenContributionByAuthor.incl seenKey

  template blockRoot: auto = contribution.beacon_block_root

  if blockRoot notin pool.bestContributions:
    let totalParticipants = countOnes(contribution.aggregation_bits)
    var initialBestContributions = BestSyncSubcommitteeContributions(
      slot: contribution.slot)

    initialBestContributions.subnets[contribution.subcommittee_index] =
      BestSyncSubcommitteeContribution(
        totalParticipants: totalParticipants,
        participationBits: contribution.aggregation_bits,
        signature: signature)

    pool.bestContributions[blockRoot] = initialBestContributions
  else:
    try:
      addAggregateAux(pool.bestContributions[blockRoot], contribution)
    except KeyError:
      raiseAssert "We have checked for the key upfront"

proc addContribution*(pool: var SyncCommitteeMsgPool,
                      scproof: SignedContributionAndProof,
                      signature: CookedSig) =
  pool.addContribution(
    scproof.message.aggregator_index, scproof.message.contribution, signature)

  if not(isNil(pool.onContributionReceived)):
    pool.onContributionReceived(scproof)

proc produceSyncAggregateAux(
    bestContributions: BestSyncSubcommitteeContributions): SyncAggregate =
  var
    aggregateSig {.noinit.}: AggregateSignature
    initialized = false
    startTime = Moment.now

  for subcommitteeIdx in SyncSubcommitteeIndex:
    if bestContributions.subnets[subcommitteeIdx].totalParticipants == 0:
      continue

    for pos, value in bestContributions.subnets[subcommitteeIdx].participationBits:
      if value:
        let globalPos = subcommitteeIdx.asInt * SYNC_SUBCOMMITTEE_SIZE + pos
        result.sync_committee_bits.setBit globalPos

    if not initialized:
      initialized = true
      aggregateSig.init(bestContributions.subnets[subcommitteeIdx].signature)
    else:
      aggregateSig.aggregate(bestContributions.subnets[subcommitteeIdx].signature)

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

proc isEpochLeadTime*(
    pool: SyncCommitteeMsgPool, epochsToSyncPeriod: uint64): bool =
  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/altair/validator.md#sync-committee-subnet-stability
  # This ensures a uniform distribution without requiring additional state:
  # (1/4)                         = 1/4, 4 slots out
  # (3/4) * (1/3)                 = 1/4, 3 slots out
  # (3/4) * (2/3) * (1/2)         = 1/4, 2 slots out
  # (3/4) * (2/3) * (1/2) * (1/1) = 1/4, 1 slot out
  doAssert epochsToSyncPeriod > 0
  epochsToSyncPeriod == 1 or pool.rng[].rand(epochsToSyncPeriod - 1) == 0
