# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[algorithm, sequtils, sets, tables],
  stew/shims/hashes,
  eth/p2p/discoveryv5/random2,
  chronicles,
  ../spec/[crypto, digest, forks],
  ../spec/datatypes/altair

export hashes, sets, tables, altair

logScope:
  topics = "syncpool"

const
  syncCommitteeMsgsRetentionSlots = 3
    ## How many slots to retain sync committee
    ## messsages before discarding them.

type
  SyncCommitteeMsgKey = object
    originator: uint64  # ValidatorIndex to avoid invalid values
    slot: Slot
    subcommitteeIdx: uint64  # SyncSubcommitteeIndex to avoid invalid values

  TrustedSyncCommitteeMsg* = object
    subcommitteeIdx*: SyncSubcommitteeIndex
    positionInCommittee*: uint64
    signature*: CookedSig

  BestSyncSubcommitteeContribution* = object
    totalParticipants*: int
    participationBits*: SyncCommitteeAggregationBits
    signature*: CookedSig

  BestSyncSubcommitteeContributions* = object
    subnets*: array[SYNC_COMMITTEE_SUBNET_COUNT,
                    BestSyncSubcommitteeContribution]

  OnSyncContributionCallback* =
    proc(data: SignedContributionAndProof) {.gcsafe, raises: [].}

  # Messages from different slots / forks may sign the same beacon block root.
  # Messages across slots are compatible, but not across forks (signing root).
  # Messages from different periods have different signers, so are incompatible.
  # Note that the sync committee is determined by `message.slot + 1`, the fork
  # is determined by `message.slot`, and both can be different from `bid.slot`.
  SyncMsgTarget = object
    bid: BlockId  # Based on message `beacon_block_root`
    period: SyncCommitteePeriod  # Based on message `slot + 1`
    fork: ConsensusFork  # Based on message `slot`

  SyncCommitteeMsgPool* = object
    seenSyncMsgByAuthor*: Table[SyncCommitteeMsgKey, Eth2Digest]
    seenContributionByAuthor*: HashSet[SyncCommitteeMsgKey]
    syncMessages*: Table[SyncMsgTarget, seq[TrustedSyncCommitteeMsg]]
    bestContributions*: Table[SyncMsgTarget, BestSyncSubcommitteeContributions]
    onContributionReceived*: OnSyncContributionCallback

    rng: ref HmacDrbgContext
    cfg: RuntimeConfig

func hash*(x: SyncCommitteeMsgKey): Hash =
  hashAllFields(x)

func toSyncMsgTarget(
    cfg: RuntimeConfig, bid: BlockId, slot: Slot): SyncMsgTarget =
  SyncMsgTarget(
    bid: bid,
    period: (slot + 1).sync_committee_period,
    fork: cfg.consensusForkAtEpoch(slot.epoch))

func hash(x: SyncMsgTarget): Hash =
  hashAllFields(x)

func `<`(x, y: SyncMsgTarget): bool =
  if x.bid.slot != y.bid.slot:
    x.bid.slot < y.bid.slot
  elif x.period != y.period:
    x.period < y.period
  else:
    x.fork < y.fork

func init*(T: type SyncCommitteeMsgPool,
           rng: ref HmacDrbgContext,
           cfg: RuntimeConfig,
           onSyncContribution: OnSyncContributionCallback = nil
          ): SyncCommitteeMsgPool =
  T(rng: rng, cfg: cfg, onContributionReceived: onSyncContribution)

func pruneData*(pool: var SyncCommitteeMsgPool, slot: Slot, force = false) =
  ## This should be called at the end of slot.
  clear pool.seenContributionByAuthor
  clear pool.seenSyncMsgByAuthor

  if slot < syncCommitteeMsgsRetentionSlots:
    return

  # Messages signing a `beacon_block_root` may remain valid over multiple slots.
  # Therefore, we filter by the targeted `BlockId` instead of message `slot`.
  let
    minSlotToRetain = slot - syncCommitteeMsgsRetentionSlots
    minEntriesToKeep = if force: 0 else: syncCommitteeMsgsRetentionSlots

  template pruneTable(table: untyped) =
    if table.len > minEntriesToKeep:
      var targets = table.keys().toSeq()
      targets.sort(order = SortOrder.Descending)
      for i in minEntriesToKeep ..< targets.len:
        if targets[i].bid.slot < minSlotToRetain:
          table.del targets[i]

  pruneTable pool.syncMessages
  pruneTable pool.bestContributions

func isSeen*(
    pool: SyncCommitteeMsgPool,
    msg: SyncCommitteeMessage,
    subcommitteeIdx: SyncSubcommitteeIndex,
    headBid: BlockId): bool =
  let seenKey = SyncCommitteeMsgKey(
    originator: msg.validator_index,  # Might be unvalidated at this point
    slot: msg.slot,
    subcommitteeIdx: subcommitteeIdx.uint64)
  return
    if seenKey notin pool.seenSyncMsgByAuthor:
      false
    elif msg.beacon_block_root == headBid.root:
      pool.seenSyncMsgByAuthor.getOrDefault(seenKey) == headBid.root
    else:
      true

proc addSyncCommitteeMessage*(
    pool: var SyncCommitteeMsgPool,
    slot: Slot,
    bid: BlockId,
    validatorIndex: uint64,
    signature: CookedSig,
    subcommitteeIdx: SyncSubcommitteeIndex,
    positionsInCommittee: seq[uint64]) =
  let seenKey = SyncCommitteeMsgKey(
    originator: validatorIndex,
    slot: slot,
    subcommitteeIdx: subcommitteeIdx.uint64)
  pool.seenSyncMsgByAuthor[seenKey] = bid.root

  func registerVotes(votes: var seq[TrustedSyncCommitteeMsg]) =
    for position in positionsInCommittee:
      block addVote:
        for vote in votes:
          if vote.subcommitteeIdx == subcommitteeIdx and
              vote.positionInCommittee == position:
            break addVote
        votes.add TrustedSyncCommitteeMsg(
          subcommitteeIdx: subcommitteeIdx,
          positionInCommittee: position,
          signature: signature)
  let target = pool.cfg.toSyncMsgTarget(bid, slot)
  pool.syncMessages.mgetOrPut(target, @[]).registerVotes()

  debug "Sync committee message resolved",
    slot = slot, blockRoot = shortLog(target.bid.root), validatorIndex

func computeAggregateSig(votes: seq[TrustedSyncCommitteeMsg],
                         subcommitteeIdx: SyncSubcommitteeIndex,
                         contribution: var SyncCommitteeContribution): bool =
  var
    aggregateSig {.noinit.}: AggregateSignature
    initialized = false

  contribution.aggregation_bits.reset()
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
  else:
    contribution.signature = ValidatorSig.infinity

  initialized

func produceContribution*(
    pool: SyncCommitteeMsgPool,
    slot: Slot,
    headBid: BlockId,
    subcommitteeIdx: SyncSubcommitteeIndex,
    outContribution: var SyncCommitteeContribution): bool =
  let target = pool.cfg.toSyncMsgTarget(headBid, slot)
  if target in pool.syncMessages:
    outContribution.slot = slot
    outContribution.beacon_block_root = headBid.root
    outContribution.subcommittee_index = subcommitteeIdx.asUInt64
    try:
      computeAggregateSig(pool.syncMessages[target],
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
    contribution: SyncCommitteeContribution,
    bid: BlockId): bool =
  ## Return true iff the given contribution brings no new information compared
  ## to the contributions already seen in the pool, ie if the contriubution is a
  ## subset of the best contribution so far
  let target = pool.cfg.toSyncMsgTarget(bid, contribution.slot)
  pool.bestContributions.withValue(target, best):
    return best[].covers(contribution)

  return false

proc addContribution(pool: var SyncCommitteeMsgPool,
                     aggregator_index: uint64,
                     contribution: SyncCommitteeContribution,
                     bid: BlockId,
                     signature: CookedSig) =
  let seenKey = SyncCommitteeMsgKey(
    originator: aggregator_index,
    slot: contribution.slot,
    subcommitteeIdx: contribution.subcommittee_index)
  pool.seenContributionByAuthor.incl seenKey

  let target = pool.cfg.toSyncMsgTarget(bid, contribution.slot)
  if target notin pool.bestContributions:
    let totalParticipants = countOnes(contribution.aggregation_bits)
    var initialBestContributions = BestSyncSubcommitteeContributions()

    initialBestContributions.subnets[contribution.subcommittee_index] =
      BestSyncSubcommitteeContribution(
        totalParticipants: totalParticipants,
        participationBits: contribution.aggregation_bits,
        signature: signature)

    pool.bestContributions[target] = initialBestContributions
  else:
    try:
      addAggregateAux(pool.bestContributions[target], contribution)
    except KeyError:
      raiseAssert "We have checked for the key upfront"

proc addContribution*(pool: var SyncCommitteeMsgPool,
                      scproof: SignedContributionAndProof,
                      bid: BlockId,
                      signature: CookedSig) =
  pool.addContribution(
    scproof.message.aggregator_index,
    scproof.message.contribution,
    bid, signature)

  if not(isNil(pool.onContributionReceived)):
    pool.onContributionReceived(scproof)

proc produceSyncAggregateAux(
    contributions: BestSyncSubcommitteeContributions): SyncAggregate =
  var
    aggregateSig {.noinit.}: AggregateSignature
    initialized = false
    startTime = Moment.now
    aggregate: SyncAggregate
  for subcommitteeIdx in SyncSubcommitteeIndex:
    if contributions.subnets[subcommitteeIdx].totalParticipants == 0:
      continue

    for pos, value in contributions.subnets[subcommitteeIdx].participationBits:
      if value:
        let globalPos = subcommitteeIdx.asInt * SYNC_SUBCOMMITTEE_SIZE + pos
        aggregate.sync_committee_bits.setBit globalPos

    if not initialized:
      initialized = true
      aggregateSig.init(contributions.subnets[subcommitteeIdx].signature)
    else:
      aggregateSig.aggregate(contributions.subnets[subcommitteeIdx].signature)

  if initialized:
    aggregate.sync_committee_signature = aggregateSig.finish.toValidatorSig
  else:
    aggregate.sync_committee_signature = ValidatorSig.infinity

  let duration = Moment.now - startTime
  debug "SyncAggregate produced", duration,
         bits = aggregate.sync_committee_bits

  aggregate

proc produceSyncAggregate*(
    pool: SyncCommitteeMsgPool,
    bid: BlockId,
    signatureSlot: Slot): SyncAggregate =
  # Sync committee signs previous slot, relative to when new block is produced
  let target = pool.cfg.toSyncMsgTarget(bid, max(signatureSlot, 1.Slot) - 1)
  if target in pool.bestContributions:
    try:
      produceSyncAggregateAux(pool.bestContributions[target])
    except KeyError:
      raiseAssert "We have checked for the key upfront"
  else:
    SyncAggregate.init()

proc isEpochLeadTime*(
    pool: SyncCommitteeMsgPool, epochsToSyncPeriod: uint64): bool =
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#sync-committee-subnet-stability
  # This ensures a uniform distribution without requiring additional state:
  # (1/4)                         = 1/4, 4 slots out
  # (3/4) * (1/3)                 = 1/4, 3 slots out
  # (3/4) * (2/3) * (1/2)         = 1/4, 2 slots out
  # (3/4) * (2/3) * (1/2) * (1/1) = 1/4, 1 slot out
  doAssert epochsToSyncPeriod > 0
  epochsToSyncPeriod == 1 or pool.rng[].rand(epochsToSyncPeriod - 1) == 0
