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
  std/macros,
  stew/assign2,
  json_serialization/types as jsonTypes,
  ../../ssz/types as sszTypes, ../crypto, ../digest, ../presets

import ./base
export base

const
  # https://github.com/ethereum/eth2.0-specs/blob/34cea67b91/specs/lightclient/beacon-chain.md#misc-1
  SYNC_COMMITTEE_SIZE* = 1024
  SYNC_COMMITTEE_PUBKEY_AGGREGATES_SIZE* = 64

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#incentivization-weights
  TIMELY_HEAD_WEIGHT* = 12
  TIMELY_SOURCE_WEIGHT* = 12
  TIMELY_TARGET_WEIGHT* = 24
  SYNC_REWARD_WEIGHT* = 8
  WEIGHT_DENOMINATOR* = 64

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/validator.md#misc
  TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE* = 4
  SYNC_COMMITTEE_SUBNET_COUNT* = 8

type
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#syncaggregate
  SyncAggregate* = object
    sync_committee_bits*: BitArray[SYNC_COMMITTEE_SIZE]
    sync_committee_signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#synccommittee
  SyncCommittee* = object
    pubkeys*: HashArray[Limit SYNC_COMMITTEE_SIZE, ValidatorPubKey]
    pubkey_aggregates*:
      HashArray[
        Limit SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_PUBKEY_AGGREGATES_SIZE,
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
  
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.2/specs/altair/beacon-chain.md#participation-flag-in:w
  # dices
  ValidatorFlag* = enum
    TIMELY_HEAD_FLAG = 0
    TIMELY_SOURCE_FLAG = 1
    TIMELY_TARGET_FLAG = 2
