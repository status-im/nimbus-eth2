# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[deques, streams, tables, hashes, options],
  stew/endians2,
  ./spec/datatypes/[phase0, altair],
  ./spec/keystore,
  ./consensus_object_pools/block_pools_types,
  ./fork_choice/fork_choice_types,
  ./validators/slashing_protection

export deques, tables, hashes, options, block_pools_types

const
  ATTESTATION_LOOKBACK* =
    min(24'u64, SLOTS_PER_EPOCH) + MIN_ATTESTATION_INCLUSION_DELAY
    ## The number of slots we'll keep track of in terms of "free" attestations
    ## that potentially could be added to a newly created block

type
  # #############################################
  #
  #             Attestation Pool
  #
  # #############################################
  OnAttestationCallback* = proc(data: Attestation) {.gcsafe, raises: [Defect].}

  Validation* = object
    ## Validations collect a set of signatures for a distict attestation - in
    ## eth2, a single bit is used to keep track of which signatures have been
    ## added to the aggregate meaning that only non-overlapping aggregates may
    ## be further combined.
    aggregation_bits*: CommitteeValidatorsBits
    aggregate_signature*: AggregateSignature

  AttestationEntry* = object
    ## Each entry holds the known signatures for a particular, distinct vote
    data*: AttestationData
    committee_len*: int
    singles*: Table[int, CookedSig] ## \
      ## On the attestation subnets, only attestations with a single vote are
      ## allowed - these can be collected separately to top up aggregates with -
      ## here we collect them by mapping index in committee to a vote
    aggregates*: seq[Validation]

  AttestationTable* = Table[Eth2Digest, AttestationEntry]
    ## Depending on the world view of the various validators, they may have
    ## voted on different states - this map keeps track of each vote keyed by
    ## hash_tree_root(AttestationData)

  AttestationPool* = object
    ## The attestation pool keeps track of all attestations that potentially
    ## could be added to a block during block production.
    ## These attestations also contribute to the fork choice, which combines
    ## "free" attestations with those found in past blocks - these votes
    ## are tracked separately in the fork choice.

    candidates*: array[ATTESTATION_LOOKBACK, AttestationTable] ## \
      ## We keep one item per slot such that indexing matches slot number
      ## together with startingSlot

    startingSlot*: Slot ## \
    ## Generally, we keep attestations only until a slot has been finalized -
    ## after that, they may no longer affect fork choice.

    dag*: ChainDAGRef
    quarantine*: QuarantineRef

    forkChoice*: ForkChoice

    nextAttestationEpoch*: seq[tuple[subnet: Epoch, aggregate: Epoch]] ## \
    ## sequence based on validator indices

    onAttestationAdded*: OnAttestationCallback

  SyncCommitteeMsgKey* = object
    originator*: ValidatorIndex
    slot*: Slot
    committeeIdx*: SyncCommitteeIndex

  TrustedSyncCommitteeMsg* = object
    slot*: Slot
    committeeIdx*: SyncCommitteeIndex
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

  SyncCommitteeMsgPoolRef* = ref SyncCommitteeMsgPool

  # #############################################
  #
  #              Validator Pool
  #
  # #############################################
  ValidatorKind* {.pure.} = enum
    Local, Remote

  ValidatorConnection* = object
    inStream*: Stream
    outStream*: Stream
    pubKeyStr*: string

  ValidatorPrivateItem* = object
    privateKey*: ValidatorPrivKey
    description*: Option[string]
    path*: Option[KeyPath]
    uuid*: Option[string]
    version*: Option[uint64]

  AttachedValidator* = ref object
    pubKey*: ValidatorPubKey
    case kind*: ValidatorKind
    of ValidatorKind.Local:
      data*: ValidatorPrivateItem
    of ValidatorKind.Remote:
      connection*: ValidatorConnection

    # The index at which this validator has been observed in the chain -
    # it does not change as long as there are no reorgs on eth1 - however, the
    # index might not be valid in all eth2 histories, so it should not be
    # assumed that a valid index is stored here!
    index*: Option[ValidatorIndex]

    # Cache the latest slot signature - the slot signature is used to determine
    # if the validator will be aggregating (in the near future)
    slotSignature*: Option[tuple[slot: Slot, signature: ValidatorSig]]

  ValidatorPool* = object
    validators*: Table[ValidatorPubKey, AttachedValidator]
    slashingProtection*: SlashingProtectionDB

  AttesterDuty* = object
    subnet*: SubnetId
    slot*: Slot
    isAggregator*: bool

  AttestationSubnets* = object
    enabled*: bool

    subscribedSubnets*: BitArray[ATTESTATION_SUBNET_COUNT] ##\
      ## All subnets we're current subscribed to

    stabilitySubnets*: seq[tuple[subnet_id: SubnetId, expiration: Epoch]] ##\
      ## The subnets on which we listen and broadcast gossip traffic to maintain
      ## the health of the network - these are advertised in the ENR
    nextCycleEpoch*: Epoch

    # Used to track the next attestation and proposal slots using an
    # epoch-relative coordinate system. Doesn't need initialization.
    attestingSlots*: array[2, uint32]
    proposingSlots*: array[2, uint32]
    lastCalculatedEpoch*: Epoch

    knownValidators*: Table[ValidatorIndex, Slot]
      ## Validators that we've recently seen - we'll subscribe to one stability
      ## subnet for each such validator - the slot is used to expire validators
      ## that no longer are posting duties

    duties*: seq[AttesterDuty] ##\
      ## Known aggregation duties in the near future - before each such
      ## duty, we'll subscribe to the corresponding subnet to collect

func shortLog*(v: AttachedValidator): string = shortLog(v.pubKey)

func hash*(x: SyncCommitteeMsgKey): Hash =
  hashData(unsafeAddr x, sizeof(x))
