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


#  std/[macros, intsets, json, strutils, tables],
#  stew/[assign2, byteutils], chronicles,
#  json_serialization/types as jsonTypes,
#  ../../ssz/types as sszTypes, ../crypto, ../digest, ../presets

import
  std/macros,
  stew/assign2,
  json_serialization/types as jsonTypes,
  ../../ssz/types as sszTypes, ../crypto, ../digest, ../presets

import ./base, ./phase0
export base

const
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#incentivization-weights
  TIMELY_HEAD_WEIGHT* = 12
  TIMELY_SOURCE_WEIGHT* = 12
  TIMELY_TARGET_WEIGHT* = 24
  SYNC_REWARD_WEIGHT* = 8
  WEIGHT_DENOMINATOR* = 64

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/validator.md#misc
  TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE* = 4
  SYNC_COMMITTEE_SUBNET_COUNT* = 8

let
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#misc
  # Cannot be computed at compile-time due to importc dependency
  G2_POINT_AT_INFINITY* = ValidatorSig.fromRaw([
    0xc0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0])

type
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#custom-types
  ParticipationFlags* = distinct uint8

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#syncaggregate
  SyncAggregate* = object
    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE]
    sync_committee_signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#synccommittee
  SyncCommittee* = object
    pubkeys*: HashArray[Limit SYNC_COMMITTEE_SIZE, ValidatorPubKey]
    pubkey_aggregates*:
      HashArray[
        Limit SYNC_COMMITTEE_SIZE div SYNC_PUBKEYS_PER_AGGREGATE,
        ValidatorPubKey]

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/validator.md#synccommitteesignature
  SyncCommitteeSignature* = object
    slot*: Slot ##\
    ## Slot to which this contribution pertains

    beacon_block_root*: Eth2Digest ##\
    ## Block root for this signature

    validator_index*: uint64 ##\
    ## Index of the validator that produced this signature

    signature*: ValidatorSig ##\
    ## Signature by the validator over the block root of `slot`

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/validator.md#synccommitteecontribution
  SyncCommitteeContribution* = object
    slot*: Slot ##\
    ## Slot to which this contribution pertains

    beacon_block_root*: Eth2Digest ##\
    ## Block root for this contribution

    subcommittee_index*: uint64 ##\
    ## The subcommittee this contribution pertains to out of the broader sync
    ## committee

    aggregation_bits*:
      BitArray[SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT] ##\
    ## A bit is set if a signature from the validator at the corresponding
    ## index in the subcommittee is present in the aggregate `signature`.

    signature*: ValidatorSig  ##\
    ## Signature by the validator(s) over the block root of `slot`

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/validator.md#contributionandproof
  ContributionAndProof* = object
    aggregator_index*: uint64
    contribution*: SyncCommitteeContribution
    selection_proof*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/validator.md#signedcontributionandproof
  SignedContributionAndProof* = object
    message*: ContributionAndProof
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/validator.md#synccommitteesigningdata
  SyncCommitteeSigningData* = object
    slot*: Slot
    subcommittee_index*: uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#participation-flag-indices
  ParticipationFlag* = enum
    TIMELY_HEAD_FLAG_INDEX = 0
    TIMELY_SOURCE_FLAG_INDEX = 1
    TIMELY_TARGET_FLAG_INDEX = 2

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#beaconstate
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

    # Light client sync committees
    current_sync_committee*: SyncCommittee
    next_sync_committee*: SyncCommittee

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  # HF1 implies knowledge of phase 0, and this saves creating some other
  # module to merge such knowledge. Another approach is to have imported
  # set of phase 0/HF1 symbols be independently combined by each module,
  # when necessary, but that spreads such detailed abstraction knowledge
  # more widely through codebase than strictly required. Do not export a
  # phase 0 version of symbols; anywhere which specially handles it will
  # have to do so itself.
  SomeBeaconState* = BeaconState | phase0.BeaconState

# TODO when https://github.com/nim-lang/Nim/issues/14440 lands in Status's Nim,
# switch proc {.noSideEffect.} to func.
proc `or`*(x, y: ParticipationFlags) : ParticipationFlags {.borrow, noSideEffect.}
proc `and`*(x, y: ParticipationFlags) : ParticipationFlags {.borrow, noSideEffect.}
proc `==`*(x, y: ParticipationFlags) : bool {.borrow, noSideEffect.}

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
