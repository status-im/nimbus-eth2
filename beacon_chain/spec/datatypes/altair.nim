# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Types specific to altair (i.e. known to have changed across hard forks) - see
# `base` for types and guidelines common across forks

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

{.push raises: [].}

import
  std/[typetraits, sets, hashes],
  chronicles,
  stew/[bitops2, objects],
  "."/[base, phase0]

export base, sets

from ssz_serialization/proofs import GeneralizedIndex
export proofs.GeneralizedIndex

type
  TimelyFlag* {.pure.} = enum
    TIMELY_SOURCE_FLAG_INDEX
    TIMELY_TARGET_FLAG_INDEX
    TIMELY_HEAD_FLAG_INDEX

static:
  # Verify that ordinals follow spec values (the spec uses these as shifts for bit flags)
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#participation-flag-indices
  doAssert ord(TIMELY_SOURCE_FLAG_INDEX) == 0
  doAssert ord(TIMELY_TARGET_FLAG_INDEX) == 1
  doAssert ord(TIMELY_HEAD_FLAG_INDEX) == 2

const
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#incentivization-weights
  TIMELY_SOURCE_WEIGHT* = 14
  TIMELY_TARGET_WEIGHT* = 26
  TIMELY_HEAD_WEIGHT* = 14
  SYNC_REWARD_WEIGHT* = 2
  PROPOSER_WEIGHT* = 8
  WEIGHT_DENOMINATOR* = 64

  PARTICIPATION_FLAG_WEIGHTS*: array[TimelyFlag, uint64] =
    [uint64 TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT, TIMELY_HEAD_WEIGHT]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#misc
  TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE* = 16
  SYNC_COMMITTEE_SUBNET_COUNT* = 4

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#constants
  # All of these indices are rooted in `BeaconState`.
  # The first member (`genesis_time`) is 32, subsequent members +1 each.
  # If there are ever more than 32 members in `BeaconState`, indices change!
  # `FINALIZED_ROOT_GINDEX` is one layer deeper, i.e., `52 * 2 + 1`.
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/ssz/merkle-proofs.md
  FINALIZED_ROOT_GINDEX* = 105.GeneralizedIndex  # finalized_checkpoint > root
  CURRENT_SYNC_COMMITTEE_GINDEX* = 54.GeneralizedIndex  # current_sync_committee
  NEXT_SYNC_COMMITTEE_GINDEX* = 55.GeneralizedIndex  # next_sync_committee

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#inactivity-penalties
  INACTIVITY_SCORE_BIAS* = 4
  INACTIVITY_SCORE_RECOVERY_RATE* = 16

  SYNC_SUBCOMMITTEE_SIZE* = SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT

# "Note: The sum of the weights equal WEIGHT_DENOMINATOR."
static: doAssert TIMELY_SOURCE_WEIGHT + TIMELY_TARGET_WEIGHT +
  TIMELY_HEAD_WEIGHT + SYNC_REWARD_WEIGHT + PROPOSER_WEIGHT ==
  WEIGHT_DENOMINATOR

type
  ### New types

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#custom-types
  ParticipationFlags* = uint8

  EpochParticipationFlags* =
    distinct List[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT]
    ## Not a HashList because the list sees significant updates every block
    ## effectively making the cost of clearing the cache higher than the typical
    ## gains

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#syncaggregate
  SyncAggregate* = object
    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE]
    sync_committee_signature*: ValidatorSig

  TrustedSyncAggregate* = object
    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE]
    sync_committee_signature*: TrustedSig

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#synccommittee
  SyncCommittee* = object
    pubkeys*: HashArray[Limit SYNC_COMMITTEE_SIZE, ValidatorPubKey]
    aggregate_pubkey*: ValidatorPubKey

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#synccommitteemessage
  SyncCommitteeMessage* = object
    slot*: Slot
      ## Slot to which this contribution pertains

    beacon_block_root*: Eth2Digest
      ## Block root for this signature

    validator_index*: uint64 # `ValidatorIndex` after validation
      ## Index of the validator that produced this signature

    signature*: ValidatorSig
      ## Signature by the validator over the block root of `slot`

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#synccommitteecontribution
  SyncCommitteeAggregationBits* =
    BitArray[SYNC_SUBCOMMITTEE_SIZE]

  SyncCommitteeContribution* = object
    slot*: Slot
      ## Slot to which this contribution pertains

    beacon_block_root*: Eth2Digest
      ## Block root for this contribution

    subcommittee_index*: uint64 # `SyncSubcommitteeIndex` after validation
      ## The subcommittee this contribution pertains to out of the broader sync
      ## committee

    aggregation_bits*: SyncCommitteeAggregationBits
      ## A bit is set if a signature from the validator at the corresponding
      ## index in the subcommittee is present in the aggregate `signature`.

    signature*: ValidatorSig
      ## Signature by the validator(s) over the block root of `slot`

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#contributionandproof
  ContributionAndProof* = object
    aggregator_index*: uint64 # `ValidatorIndex` after validation
    contribution*: SyncCommitteeContribution
    selection_proof*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#signedcontributionandproof
  SignedContributionAndProof* = object
    message*: ContributionAndProof
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/validator.md#syncaggregatorselectiondata
  SyncAggregatorSelectionData* = object
    slot*: Slot
    subcommittee_index*: uint64 # `SyncSubcommitteeIndex` after validation

  ### Modified/overloaded

  FinalityBranch* =
    array[log2trunc(FINALIZED_ROOT_GINDEX), Eth2Digest]

  CurrentSyncCommitteeBranch* =
    array[log2trunc(CURRENT_SYNC_COMMITTEE_GINDEX), Eth2Digest]

  NextSyncCommitteeBranch* =
    array[log2trunc(NEXT_SYNC_COMMITTEE_GINDEX), Eth2Digest]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientheader
  LightClientHeader* = object
    beacon*: BeaconBlockHeader
      ## Beacon block header

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientbootstrap
  LightClientBootstrap* = object
    header*: LightClientHeader
      ## Header matching the requested beacon block root

    current_sync_committee*: SyncCommittee
      ## Current sync committee corresponding to `header.beacon.state_root`
    current_sync_committee_branch*: CurrentSyncCommitteeBranch

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientupdate
  LightClientUpdate* = object
    attested_header*: LightClientHeader
      ## Header attested to by the sync committee

    next_sync_committee*: SyncCommittee
      ## Next sync committee corresponding to
      ## `attested_header.beacon.state_root`
    next_sync_committee_branch*: NextSyncCommitteeBranch

    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header*: LightClientHeader
    finality_branch*: FinalityBranch

    sync_aggregate*: SyncAggregate
      ## Sync committee aggregate signature
    signature_slot*: Slot
      ## Slot at which the aggregate signature was created (untrusted)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientfinalityupdate
  LightClientFinalityUpdate* = object
    # Header attested to by the sync committee
    attested_header*: LightClientHeader

    # Finalized header corresponding to `attested_header.beacon.state_root`
    finalized_header*: LightClientHeader
    finality_branch*: FinalityBranch

    # Sync committee aggregate signature
    sync_aggregate*: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot*: Slot

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientoptimisticupdate
  LightClientOptimisticUpdate* = object
    # Header attested to by the sync committee
    attested_header*: LightClientHeader

    # Sync committee aggregate signature
    sync_aggregate*: SyncAggregate
    # Slot at which the aggregate signature was created (untrusted)
    signature_slot*: Slot

  SomeLightClientUpdateWithSyncCommittee* =
    LightClientUpdate

  SomeLightClientUpdateWithFinality* =
    LightClientUpdate |
    LightClientFinalityUpdate

  SomeLightClientUpdate* =
    LightClientUpdate |
    LightClientFinalityUpdate |
    LightClientOptimisticUpdate

  SomeLightClientObject* =
    LightClientBootstrap |
    SomeLightClientUpdate

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#lightclientstore
  LightClientStore* = object
    finalized_header*: LightClientHeader
      ## Header that is finalized

    current_sync_committee*: SyncCommittee
      ## Sync committees corresponding to the finalized header
    next_sync_committee*: SyncCommittee

    best_valid_update*: Opt[LightClientUpdate]
      ## Best available header to switch finalized head to
      ## if we see nothing else

    optimistic_header*: LightClientHeader
      ## Most recent available reasonably-safe header

    previous_max_active_participants*: uint64
      ## Max number of active participants in a sync committee
      ## (used to compute safety threshold)
    current_max_active_participants*: uint64

  InactivityScores* = HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#beaconstate
  BeaconState* = object
    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader
      ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
      ## Needed to process attestations, older to newer

    state_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    historical_roots*: HashList[Eth2Digest, Limit HISTORICAL_ROOTS_LIMIT]

    # Eth1
    eth1_data*: Eth1Data
    eth1_data_votes*:
      HashList[Eth1Data, Limit(EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)]
    eth1_deposit_index*: uint64

    # Registry
    validators*: HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT]
    balances*: HashList[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]

    # Randomness
    randao_mixes*: HashArray[Limit EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]

    # Slashings
    slashings*: HashArray[Limit EPOCHS_PER_SLASHINGS_VECTOR, Gwei]
      ## Per-epoch sums of slashed effective balances

    # Participation
    previous_epoch_participation*: EpochParticipationFlags
      ## [Modified in Altair]
    current_epoch_participation*: EpochParticipationFlags
      ## [Modified in Altair]

    # Finality
    justification_bits*: JustificationBits
      ## Bit set for every recent justified epoch

    previous_justified_checkpoint*: Checkpoint
    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

    # Inactivity
    inactivity_scores*: InactivityScores  # [New in Altair]

    # Light client sync committees
    current_sync_committee*: SyncCommittee     # [New in Altair]
    next_sync_committee*: SyncCommittee        # [New in Altair]

  UnslashedParticipatingBalances* = object
    previous_epoch*: array[TimelyFlag, Gwei]
    current_epoch_TIMELY_TARGET*: Gwei
    current_epoch*: Gwei # aka total_active_balance

  ParticipationFlag* {.pure.} = enum
    timelySourceAttester
    timelyTargetAttester
    timelyHeadAttester
    eligible

  ParticipationInfo* = object
    flags*: set[ParticipationFlag]
    delta*: RewardDelta

  EpochInfo* = object
    ## Information about the outcome of epoch processing
    validators*: seq[ParticipationInfo]
    balances*: UnslashedParticipatingBalances

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: BeaconBlockBody

  SigVerifiedBeaconBlock* = object
    ## A BeaconBlock that contains verified signatures
    ## but that has not been verified for state transition

    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation

    parent_root*: Eth2Digest
      ## Root hash of the previous block

    state_root*: Eth2Digest
      ## The state root, _after_ this block has been processed

    body*: SigVerifiedBeaconBlockBody

  TrustedBeaconBlock* = object
    ## When we receive blocks from outside sources, they are untrusted and go
    ## through several layers of validation. Blocks that have gone through
    ## validations can be trusted to be well-formed, with a correct signature,
    ## having a parent and applying cleanly to the state that their parent
    ## left them with.
    ##
    ## When loading such blocks from the database, to rewind states for example,
    ## it is expensive to redo the validations (in particular, the signature
    ## checks), thus `TrustedBlock` uses a `TrustedSig` type to mark that these
    ## checks can be skipped.
    ##
    ## TODO this could probably be solved with some type trickery, but there
    ##      too many bugs in nim around generics handling, and we've used up
    ##      the trickery budget in the serialization library already. Until
    ##      then, the type must be manually kept compatible with its untrusted
    ##      cousin.
    slot*: Slot
    proposer_index*: uint64 # `ValidatorIndex` after validation
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body*: TrustedBeaconBlockBody

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    # [New in Altair]
    sync_aggregate*: SyncAggregate

  SigVerifiedBeaconBlockBody* = object
    ## A BeaconBlock body with signatures verified
    ## including:
    ## - Randao reveal
    ## - Attestations
    ## - ProposerSlashing (SignedBeaconBlockHeader)
    ## - AttesterSlashing (IndexedAttestation)
    ## - SignedVoluntaryExits
    ## - SyncAggregate
    ##
    ## However:
    ## - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    # [New in Altair]
    sync_aggregate*: TrustedSyncAggregate

  SyncnetBits* = BitArray[SYNC_COMMITTEE_SUBNET_COUNT]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/p2p-interface.md#metadata
  MetaData* = object
    seq_number*: uint64
    attnets*: AttnetBits
    syncnets*: SyncnetBits

  TrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
      ## Eth1 data vote

    graffiti*: GraffitiBytes
      ## Arbitrary data

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    # [New in Altair]
    sync_aggregate*: TrustedSyncAggregate

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#signedbeaconblock
  SignedBeaconBlock* = object
    message*: BeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SigVerifiedSignedBeaconBlock* = object
    ## A SignedBeaconBlock with signatures verified
    ## including:
    ## - Block signature
    ## - BeaconBlockBody
    ##   - Randao reveal
    ##   - Attestations
    ##   - ProposerSlashing (SignedBeaconBlockHeader)
    ##   - AttesterSlashing (IndexedAttestation)
    ##   - SignedVoluntaryExits
    ##
    ##   - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    message*: SigVerifiedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  MsgTrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SomeSignedBeaconBlock* =
    SignedBeaconBlock |
    SigVerifiedSignedBeaconBlock |
    MsgTrustedSignedBeaconBlock |
    TrustedSignedBeaconBlock
  SomeBeaconBlock* =
    BeaconBlock |
    SigVerifiedBeaconBlock |
    TrustedBeaconBlock
  SomeBeaconBlockBody* =
    BeaconBlockBody |
    SigVerifiedBeaconBlockBody |
    TrustedBeaconBlockBody

  SomeSyncAggregate* = SyncAggregate | TrustedSyncAggregate

  SyncSubcommitteeIndex* = distinct uint8
  IndexInSyncCommittee* = distinct uint16

chronicles.formatIt BeaconBlock: it.shortLog
chronicles.formatIt SyncSubcommitteeIndex: uint8(it)

template `[]`*(a: auto; i: SyncSubcommitteeIndex): auto =
  a[i.asInt]

template `[]`*(arr: array[SYNC_COMMITTEE_SIZE, auto] | seq;
               idx: IndexInSyncCommittee): auto =
  arr[int idx]

makeLimitedU8(SyncSubcommitteeIndex, SYNC_COMMITTEE_SUBNET_COUNT)
makeLimitedU16(IndexInSyncCommittee, SYNC_COMMITTEE_SIZE)

template asList*(epochFlags: EpochParticipationFlags): untyped =
  List[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT] epochFlags
template asList*(epochFlags: var EpochParticipationFlags): untyped =
  let tmp = cast[ptr List[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT]](addr epochFlags)
  tmp[]

template asSeq*(epochFlags: EpochParticipationFlags): untyped =
  seq[ParticipationFlags] asList(epochFlags)

template asSeq*(epochFlags: var EpochParticipationFlags): untyped =
  let tmp = cast[ptr seq[ParticipationFlags]](addr epochFlags)
  tmp[]

template item*(epochFlags: EpochParticipationFlags, idx: ValidatorIndex): ParticipationFlags =
  asList(epochFlags)[idx]

template `[]`*(epochFlags: EpochParticipationFlags, idx: ValidatorIndex|uint64|int): ParticipationFlags =
  asList(epochFlags)[idx]

template `[]=`*(epochFlags: EpochParticipationFlags, idx: ValidatorIndex, flags: ParticipationFlags) =
  asList(epochFlags)[idx] = flags

template add*(epochFlags: var EpochParticipationFlags, flags: ParticipationFlags): bool =
  asList(epochFlags).add flags

template len*(epochFlags: EpochParticipationFlags): int =
  asList(epochFlags).len

template low*(epochFlags: EpochParticipationFlags): int =
  asSeq(epochFlags).low
template high*(epochFlags: EpochParticipationFlags): int =
  asSeq(epochFlags).high

template assign*(v: var EpochParticipationFlags, src: EpochParticipationFlags) =
  # TODO https://github.com/nim-lang/Nim/issues/21123
  mixin assign
  var tmp = cast[ptr seq[ParticipationFlags]](addr v)
  assign(tmp[], distinctBase src)

func shortLog*(v: SomeBeaconBlock): auto =
  (
    slot: shortLog(v.slot),
    proposer_index: v.proposer_index,
    parent_root: shortLog(v.parent_root),
    state_root: shortLog(v.state_root),
    eth1data: v.body.eth1_data,
    graffiti: $v.body.graffiti,
    proposer_slashings_len: v.body.proposer_slashings.len(),
    attester_slashings_len: v.body.attester_slashings.len(),
    attestations_len: v.body.attestations.len(),
    deposits_len: v.body.deposits.len(),
    voluntary_exits_len: v.body.voluntary_exits.len(),
    sync_committee_participants: v.body.sync_aggregate.num_active_participants,
    block_number: 0'u64, # Bellatrix compat
    block_hash: "",      # Bellatrix compat
    parent_hash: "",     # Bellatrix compat
    fee_recipient: "",   # Bellatrix compat
    bls_to_execution_changes_len: 0,  # Capella compat
    blob_kzg_commitments_len: 0,  # Deneb compat
  )

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func shortLog*(v: SyncCommitteeContribution): auto =
  (
    slot: shortLog(v.slot),
    beacon_block_root: shortLog(v.beacon_block_root),
    subcommittee_index: v.subcommittee_index,
    aggregation_bits: $v.aggregation_bits
  )

func shortLog*(v: SyncCommitteeMessage): auto =
  (
    slot: shortLog(v.slot),
    beacon_block_root: shortLog(v.beacon_block_root),
    validator_index: v.validator_index,
    signature: shortLog(v.signature)
  )

func init*(T: type SyncAggregate): SyncAggregate =
  SyncAggregate(sync_committee_signature: ValidatorSig.infinity)

func num_active_participants*(v: SomeSyncAggregate): int =
  countOnes(v.sync_committee_bits)

func hasSupermajoritySyncParticipation*(
    num_active_participants: uint64): bool =
  const max_active_participants = SYNC_COMMITTEE_SIZE.uint64
  num_active_participants * 3 >= static(max_active_participants * 2)

func hasSupermajoritySyncParticipation*(v: SomeSyncAggregate): bool =
  hasSupermajoritySyncParticipation(v.num_active_participants.uint64)

func shortLog*(v: SyncAggregate): auto =
  $(v.sync_committee_bits)

func shortLog*(v: ContributionAndProof): auto =
  (
    aggregator_index: v.aggregator_index,
    contribution: shortLog(v.contribution),
    selection_proof: shortLog(v.selection_proof)
  )

func shortLog*(v: SignedContributionAndProof): auto =
  (
    message: shortLog(v.message),
    signature: shortLog(v.signature)
  )

chronicles.formatIt SyncCommitteeMessage: shortLog(it)
chronicles.formatIt SyncCommitteeContribution: shortLog(it)
chronicles.formatIt ContributionAndProof: shortLog(it)
chronicles.formatIt SignedContributionAndProof: shortLog(it)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/sync-protocol.md#is_valid_light_client_header
func is_valid_light_client_header*(
    header: LightClientHeader, cfg: RuntimeConfig): bool =
  true

func shortLog*(v: LightClientHeader): auto =
  (
    beacon: shortLog(v.beacon)
  )

func shortLog*(v: LightClientBootstrap): auto =
  (
    header: shortLog(v.header)
  )

func shortLog*(v: LightClientUpdate): auto =
  (
    attested: shortLog(v.attested_header),
    has_next_sync_committee:
      v.next_sync_committee != default(typeof(v.next_sync_committee)),
    finalized: shortLog(v.finalized_header),
    num_active_participants: v.sync_aggregate.num_active_participants,
    signature_slot: v.signature_slot
  )

func shortLog*(v: LightClientFinalityUpdate): auto =
  (
    attested: shortLog(v.attested_header),
    finalized: shortLog(v.finalized_header),
    num_active_participants: v.sync_aggregate.num_active_participants,
    signature_slot: v.signature_slot
  )

func shortLog*(v: LightClientOptimisticUpdate): auto =
  (
    attested: shortLog(v.attested_header),
    num_active_participants: v.sync_aggregate.num_active_participants,
    signature_slot: v.signature_slot,
  )

chronicles.formatIt LightClientBootstrap: shortLog(it)
chronicles.formatIt LightClientUpdate: shortLog(it)
chronicles.formatIt LightClientFinalityUpdate: shortLog(it)
chronicles.formatIt LightClientOptimisticUpdate: shortLog(it)

func clear*(info: var EpochInfo) =
  info.validators.setLen(0)
  info.balances = UnslashedParticipatingBalances()

template asSigned*(
    x: SigVerifiedSignedBeaconBlock |
       MsgTrustedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

template asSigVerified*(
    x: SignedBeaconBlock |
       MsgTrustedSignedBeaconBlock |
       TrustedSignedBeaconBlock): SigVerifiedSignedBeaconBlock =
  isomorphicCast[SigVerifiedSignedBeaconBlock](x)

template asSigVerified*(
    x: BeaconBlock | TrustedBeaconBlock): SigVerifiedBeaconBlock =
  isomorphicCast[SigVerifiedBeaconBlock](x)

template asMsgTrusted*(
    x: SignedBeaconBlock |
       SigVerifiedSignedBeaconBlock |
       TrustedSignedBeaconBlock): MsgTrustedSignedBeaconBlock =
  isomorphicCast[MsgTrustedSignedBeaconBlock](x)

template asTrusted*(
    x: SignedBeaconBlock |
       SigVerifiedSignedBeaconBlock |
       MsgTrustedSignedBeaconBlock): TrustedSignedBeaconBlock =
  isomorphicCast[TrustedSignedBeaconBlock](x)

template asTrusted*(
    x: SyncAggregate): TrustedSyncAggregate =
  isomorphicCast[TrustedSyncAggregate](x)
