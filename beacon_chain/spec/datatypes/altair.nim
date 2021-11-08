# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This file contains data types that are part of the spec and thus subject to
# serialization and spec updates.
#
# The spec folder in general contains code that has been hoisted from the
# specification and that follows the spec as closely as possible, so as to make
# it easy to keep up-to-date.
#
# These datatypes are used as specifications for serialization - thus should not
# be altered outside of what the spec says. Likewise, they should not be made
# `ref` - this can be achieved by wrapping them in higher-level
# types / composition

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

{.push raises: [Defect].}

import
  std/[macros, typetraits, sets, hashes],
  chronicles,
  stew/[assign2, bitops2],
  json_serialization/types as jsonTypes

import ./base, ./phase0
export base

from ../../ssz/merkleization import GeneralizedIndex
export merkleization.GeneralizedIndex

const
  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/beacon-chain.md#incentivization-weights
  TIMELY_SOURCE_WEIGHT* = 14
  TIMELY_TARGET_WEIGHT* = 26
  TIMELY_HEAD_WEIGHT* = 14
  SYNC_REWARD_WEIGHT* = 2
  PROPOSER_WEIGHT* = 8
  WEIGHT_DENOMINATOR* = 64

  PARTICIPATION_FLAG_WEIGHTS* =
    [TIMELY_SOURCE_WEIGHT, TIMELY_TARGET_WEIGHT, TIMELY_HEAD_WEIGHT]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/altair/validator.md#misc
  TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE* = 16
  SYNC_COMMITTEE_SUBNET_COUNT* = 4

  # https://github.com/ethereum/consensus-specs/blob/v1.1.3/setup.py#L478-L479
  FINALIZED_ROOT_INDEX* = 105.GeneralizedIndex
  NEXT_SYNC_COMMITTEE_INDEX* = 55.GeneralizedIndex

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/altair/beacon-chain.md#participation-flag-indices
  TIMELY_SOURCE_FLAG_INDEX* = 0
  TIMELY_TARGET_FLAG_INDEX* = 1
  TIMELY_HEAD_FLAG_INDEX* = 2

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/beacon-chain.md#inactivity-penalties
  INACTIVITY_SCORE_BIAS* = 4
  INACTIVITY_SCORE_RECOVERY_RATE* = 16

  SYNC_SUBCOMMITTEE_SIZE* = SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT

# "Note: The sum of the weights equal WEIGHT_DENOMINATOR."
static: doAssert TIMELY_SOURCE_WEIGHT + TIMELY_TARGET_WEIGHT +
  TIMELY_HEAD_WEIGHT + SYNC_REWARD_WEIGHT + PROPOSER_WEIGHT ==
  WEIGHT_DENOMINATOR

type
  ### New types

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/beacon-chain.md#custom-types
  ParticipationFlags* = uint8

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/beacon-chain.md#syncaggregate
  SyncAggregate* = object
    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE]
    sync_committee_signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/beacon-chain.md#synccommittee
  SyncCommittee* = object
    pubkeys*: HashArray[Limit SYNC_COMMITTEE_SIZE, ValidatorPubKey]
    aggregate_pubkey*: ValidatorPubKey

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/validator.md#synccommitteemessage
  SyncCommitteeMessage* = object
    slot*: Slot ##\
    ## Slot to which this contribution pertains

    beacon_block_root*: Eth2Digest ##\
    ## Block root for this signature

    validator_index*: uint64 ##\
    ## Index of the validator that produced this signature

    signature*: ValidatorSig ##\
    ## Signature by the validator over the block root of `slot`

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/validator.md#synccommitteecontribution
  SyncCommitteeAggregationBits* =
    BitArray[SYNC_SUBCOMMITTEE_SIZE]

  SyncCommitteeContribution* = object
    slot*: Slot ##\
    ## Slot to which this contribution pertains

    beacon_block_root*: Eth2Digest ##\
    ## Block root for this contribution

    subcommittee_index*: uint64 ##\
    ## The subcommittee this contribution pertains to out of the broader sync
    ## committee

    aggregation_bits*: SyncCommitteeAggregationBits ##\
    ## A bit is set if a signature from the validator at the corresponding
    ## index in the subcommittee is present in the aggregate `signature`.

    signature*: ValidatorSig  ##\
    ## Signature by the validator(s) over the block root of `slot`

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/validator.md#contributionandproof
  ContributionAndProof* = object
    aggregator_index*: uint64
    contribution*: SyncCommitteeContribution
    selection_proof*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/validator.md#signedcontributionandproof
  SignedContributionAndProof* = object
    message*: ContributionAndProof
    signature*: ValidatorSig

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/validator.md#syncaggregatorselectiondata
  SyncAggregatorSelectionData* = object
    slot*: Slot
    subcommittee_index*: uint64

  ### Modified/overloaded

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/sync-protocol.md#lightclientsnapshot
  LightClientSnapshot* = object
    header*: BeaconBlockHeader ##\
    ## Beacon block header

    current_sync_committee*: SyncCommittee ##\
    ## Sync committees corresponding to the header

    next_sync_committee*: SyncCommittee

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/sync-protocol.md#lightclientupdate
  LightClientUpdate* = object
    header*: BeaconBlockHeader  ##\
    ## Update beacon block header

    next_sync_committee*: SyncCommittee ##\
    ## Next sync committee corresponding to the header

    next_sync_committee_branch*: array[log2trunc(NEXT_SYNC_COMMITTEE_INDEX), Eth2Digest] ##\
    ## Finality proof for the update header

    finality_header*: BeaconBlockHeader
    finality_branch*: array[log2trunc(FINALIZED_ROOT_INDEX), Eth2Digest]

    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE] ##\
    ## Sync committee aggregate signature

    sync_committee_signature*: ValidatorSig

    fork_version*: Version ##\
    ## Fork version for the aggregate signature

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/sync-protocol.md#lightclientstore
  LightClientStore* = object
    snapshot*: LightClientSnapshot
    valid_updates*: HashSet[LightClientUpdate]
      ## TODO: This will benefit from being an ordered set

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/beacon-chain.md#beaconstate
  BeaconState* = object
    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader ##\
    ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
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
    balances*: HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

    # Randomness
    randao_mixes*: HashArray[Limit EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]

    # Slashings
    slashings*: HashArray[Limit EPOCHS_PER_SLASHINGS_VECTOR, uint64] ##\
    ## Per-epoch sums of slashed effective balances

    # Participation
    previous_epoch_participation*:
      HashList[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT]
    current_epoch_participation*:
      HashList[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT]

    # Finality
    justification_bits*: uint8 ##\
    ## Bit set for every recent justified epoch
    ## Model a Bitvector[4] as a one-byte uint, which should remain consistent
    ## with ssz/hashing.

    previous_justified_checkpoint*: Checkpoint ##\
    ## Previous epoch snapshot

    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

    # Inactivity
    inactivity_scores*: HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]  # [New in Altair]

    # Light client sync committees
    current_sync_committee*: SyncCommittee     # [New in Altair]
    next_sync_committee*: SyncCommittee        # [New in Altair]

  UnslashedParticipatingBalances* = object
    previous_epoch*: array[PARTICIPATION_FLAG_WEIGHTS.len, Gwei]
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

  # https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64

    parent_root*: Eth2Digest ##\
    ## Root hash of the previous block

    state_root*: Eth2Digest ##\
    ## The state root, _after_ this block has been processed

    body*: BeaconBlockBody

  SigVerifiedBeaconBlock* = object
    ## A BeaconBlock that contains verified signatures
    ## but that has not been verified for state transition
    slot*: Slot
    proposer_index*: uint64

    parent_root*: Eth2Digest ##\
    ## Root hash of the previous block

    state_root*: Eth2Digest ##\
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
    proposer_index*: uint64
    parent_root*: Eth2Digest ##\
    state_root*: Eth2Digest ##\
    body*: TrustedBeaconBlockBody

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data ##\
    ## Eth1 data vote

    graffiti*: GraffitiBytes ##\
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
    ##
    ## - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    # [New in Altair]
    sync_aggregate*: SyncAggregate

  SyncnetBits* = BitArray[SYNC_COMMITTEE_SUBNET_COUNT]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/altair/p2p-interface.md#metadata
  MetaData* = object
    seq_number*: uint64
    attnets*: AttnetBits
    syncnets*: SyncnetBits

  TrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

    # [New in Altair]
    sync_aggregate*: SyncAggregate

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/phase0/beacon-chain.md#signedbeaconblock
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

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SomeSignedBeaconBlock* = SignedBeaconBlock | SigVerifiedSignedBeaconBlock | TrustedSignedBeaconBlock
  SomeBeaconBlock* = BeaconBlock | SigVerifiedBeaconBlock | TrustedBeaconBlock
  SomeBeaconBlockBody* = BeaconBlockBody | SigVerifiedBeaconBlockBody | TrustedBeaconBlockBody

  SyncSubcommitteeIndex* = distinct uint8

chronicles.formatIt BeaconBlock: it.shortLog
chronicles.formatIt SyncSubcommitteeIndex: uint8(it)

template asInt*(x: SyncSubcommitteeIndex): int = int(x)
template asUInt8*(x: SyncSubcommitteeIndex): uint8 = uint8(x)
template asUInt64*(x: SyncSubcommitteeIndex): uint64 = uint64(x)

template `[]`*(a: auto; i: SyncSubcommitteeIndex): auto = a[i.asInt]

template `==`*(x, y: SyncSubcommitteeIndex): bool =
  distinctBase(x) == distinctBase(y)

iterator allSyncSubcommittees*: SyncSubcommitteeIndex =
  for subcommitteeIdx in 0 ..< SYNC_COMMITTEE_SUBNET_COUNT:
    yield SyncSubcommitteeIndex(subcommitteeIdx)

template validateSyncCommitteeIndexOr*(
    networkValParam: uint64,
    elseBody: untyped): SyncSubcommitteeIndex =
  let networkVal = networkValParam
  if networkVal < SYNC_COMMITTEE_SUBNET_COUNT:
    SyncSubcommitteeIndex(networkVal)
  else:
    elseBody

template asUInt8*(x: SyncSubcommitteeIndex): uint8 = uint8(x)

Json.useCustomSerialization(BeaconState.justification_bits):
  read:
    let s = reader.readValue(string)

    if s.len != 4:
      raiseUnexpectedValue(reader, "A string with 4 characters expected")

    try:
      s.parseHexInt.uint8
    except ValueError:
      raiseUnexpectedValue(reader, "The `justification_bits` value must be a hex string")

  write:
    writer.writeValue "0x" & value.toHex

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
    sync_committee_participants: countOnes(v.body.sync_aggregate.sync_committee_bits)
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
    subnetId: v.subcommittee_index,
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

template hash*(x: LightClientUpdate): Hash =
  hash(x.header)

func clear*(info: var EpochInfo) =
  info.validators.setLen(0)
  info.balances = UnslashedParticipatingBalances()

template asSigned*(x: SigVerifiedSignedBeaconBlock | TrustedSignedBeaconBlock):
    SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

template asSigVerified*(x: SignedBeaconBlock | TrustedSignedBeaconBlock): SigVerifiedSignedBeaconBlock =
  isomorphicCast[SigVerifiedSignedBeaconBlock](x)

template asTrusted*(
    x: SignedBeaconBlock | SigVerifiedSignedBeaconBlock): TrustedSignedBeaconBlock =
  isomorphicCast[TrustedSignedBeaconBlock](x)
