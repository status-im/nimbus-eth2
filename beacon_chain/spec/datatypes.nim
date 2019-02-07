# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
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

import
  eth/common, math,
  ./crypto, ./digest

# TODO Data types:
# Presently, we're reusing the data types from the serialization (uint64) in the
# objects we pass around to the beacon chain logic, thus keeping the two
# similar. This is convenient for keeping up with the specification, but
# will eventually need a more robust approach such that we don't run into
# over- and underflows.
# Some of the open questions are being tracked here:
# https://github.com/ethereum/eth2.0-specs/issues/224
#
# The present approach causes some problems due to how Nim treats unsigned
# integers - here's no high(uint64), arithmetic support is incomplete, there's
# no over/underflow checking available
#
# Eventually, we could also differentiate between user/tainted data and
# internal state that's gone through sanity checks already.

# TODO Many of these constants should go into a config object that can be used
#      to run.. well.. a chain with different constants!
const
  # Misc
  SHARD_COUNT* = 1024 ##\
  ## Number of shards supported by the network - validators will jump around
  ## between these shards and provide attestations to their state.

  TARGET_COMMITTEE_SIZE* = 2^7 ##\
  ## Number of validators in the committee attesting to one shard
  ## Per spec:
  ## For the safety of crosslinks `TARGET_COMMITTEE_SIZE` exceeds
  ## [the recommended minimum committee size of 111](https://vitalik.ca/files/Ithaca201807_Sharding.pdf);
  ## with sufficient active validators (at least
  ## `EPOCH_LENGTH * TARGET_COMMITTEE_SIZE`), the shuffling algorithm ensures
  ## committee sizes at least `TARGET_COMMITTEE_SIZE`. (Unbiasable randomness
  ## with a Verifiable Delay Function (VDF) will improve committee robustness
  ## and lower the safe minimum committee size.)

  EJECTION_BALANCE* = 2'u64^4 * 10'u64^9 ##\
  ## Once the balance of a validator drops below this, it will be ejected from
  ## the validator pool

  MAX_BALANCE_CHURN_QUOTIENT* = 2^5 ##\
  ## At most `1/MAX_BALANCE_CHURN_QUOTIENT` of the validators can change during
  ## each validator registry change.

  BEACON_CHAIN_SHARD_NUMBER* = not 0'u64 # 2^64 - 1 in spec

  MAX_INDICES_PER_SLASHABLE_VOTE* = 2^12 ##\
  ## votes

  MAX_WITHDRAWALS_PER_EPOCH* = 4 # withdrawals

  # Deposit contract
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md
  DEPOSIT_CONTRACT_TREE_DEPTH* = 2^5

  MIN_DEPOSIT_AMOUNT* = 2'u64^0 * 10'u64^9 ##\
  ## Minimum amounth of ETH that can be deposited in one call - deposits can
  ## be used either to top up an existing validator or commit to a new one
  MAX_DEPOSIT_AMOUNT* = 2'u64^5 * 10'u64^9 ##\
  ## Maximum amounth of ETH that can be deposited in one call

  # Time parameter, here so that GENESIS_EPOCH can access it
  EPOCH_LENGTH* = 64 ##\
  ## (~6.4 minutes)
  ## slots that make up an epoch, at the end of which more heavy
  ## processing is done

  # Initial values
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#initial-values
  GENESIS_FORK_VERSION* = 0'u64
  GENESIS_SLOT* = 2'u64^63
  GENESIS_EPOCH* = GENESIS_SLOT div EPOCH_LENGTH # slot_to_epoch(GENESIS_SLOT)
  GENESIS_START_SHARD* = 0'u64
  FAR_FUTURE_EPOCH* = not 0'u64 # 2^64 - 1 in spec
  ZERO_HASH* = Eth2Digest()
  EMPTY_SIGNATURE* = ValidatorSig()
  BLS_WITHDRAWAL_PREFIX_BYTE* = 0'u8

  # Time parameters
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#time-parameters
  SLOT_DURATION* = 6'u64 ## \
  ## TODO consistent time unit across projects, similar to C++ chrono?

  MIN_ATTESTATION_INCLUSION_DELAY* = 2'u64^2 ##\
  ## (24 seconds)
  ## Number of slots that attestations stay in the attestation
  ## pool before being added to a block.
  ## The attestation delay exists so that there is time for attestations to
  ## propagate before the block is created.
  ## When creating an attestation, the validator will look at the best
  ## information known to at that time, and may not revise it during the same
  ## slot (see `is_double_vote`) - the delay gives the validator a chance to
  ## wait towards the end of the slot and still have time to publish the
  ## attestation.

  SEED_LOOKAHEAD* = 1 ##\
  ## epochs (~6.4 minutes)

  ENTRY_EXIT_DELAY* = 4 ##\
  ## epochs (~25.6 minutes)

  ETH1_DATA_VOTING_PERIOD* = 2'u64^4 ##\
  ## epochs (~1.7 hours)

  MIN_VALIDATOR_WITHDRAWAL_EPOCHS* = 2'u64^8 ##\
  ## epochs (~27 hours)

  # State list lengths
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#state-list-lengths
  LATEST_BLOCK_ROOTS_LENGTH* = 2'u64^13
  LATEST_RANDAO_MIXES_LENGTH* = 2'u64^13
  LATEST_INDEX_ROOTS_LENGTH* = 2'u64^13
  LATEST_PENALIZED_EXIT_LENGTH* = 8192 # epochs

  # Reward and penalty quotients
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#reward-and-penalty-quotients
  BASE_REWARD_QUOTIENT* = 2'u64^5 ##\
  ## The `BASE_REWARD_QUOTIENT` parameter dictates the per-epoch reward. It
  ## corresponds to ~2.54% annual interest assuming 10 million participating
  ## ETH in every epoch.
  WHISTLEBLOWER_REWARD_QUOTIENT* = 2'u64^9
  INCLUDER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^24

  # Status flags
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#status-flags
  # Could model this with enum, but following spec closely here
  INITIATED_EXIT* = 1'u64
  WITHDRAWABLE* = 2'u64

  # Max operations per block
  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#max-operations-per-block
  MAX_PROPOSER_SLASHINGS* = 2^4
  MAX_ATTESTER_SLASHINGS* = 2^0
  MAX_ATTESTATIONS* = 2^7
  MAX_DEPOSITS* = 2^4
  MAX_EXITS* = 2^4

type
  ValidatorIndex* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around
  SlotNumber* = uint64
  EpochNumber* = uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#proposerslashing
  ProposerSlashing* = object
    proposer_index*: ValidatorIndex
    proposal_data_1*: ProposalSignedData
    proposal_signature_1*: ValidatorSig
    proposal_data_2*: ProposalSignedData
    proposal_signature_2*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#attesterslashing
  AttesterSlashing* = object
    slashable_attestation_1*: SlashableAttestation ## \
    ## First batch of votes
    slashable_attestation_2*: SlashableAttestation ## \
    ## Second batch of votes

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#slashableattestation
  SlashableAttestation* = object
    validator_indices*: seq[uint64] ##\
    ## Validator indices

    data*: AttestationData ## \
    ## Attestation data

    custody_bitfield*: seq[byte] ##\
    ## Custody bitfield

    aggregate_signature*: ValidatorSig ## \
    ## Aggregate signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#attestation
  Attestation* = object
    aggregation_bitfield*: seq[byte] ##\
    ## The attesters that are represented in the aggregate signature - each
    ## bit represents an index in `ShardCommittee.committee`

    data*: AttestationData
    custody_bitfield*: seq[byte] ##\
    ## Custody bitfield
    aggregate_signature*: ValidatorSig ##\
    ## Aggregate signature of the validators in `custody_bitfield`

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#attestationdata
  AttestationData* = object
    slot*: uint64
    shard*: uint64
    beacon_block_root*: Eth2Digest ##\
    ## Hash of the block we're signing

    epoch_boundary_root*: Eth2Digest ##\
    ## Hash of the ancestor at the cycle boundary

    shard_block_root*: Eth2Digest ##\
    ## Shard block hash being attested to

    latest_crosslink_root*: Eth2Digest ##\
    ## Last crosslink hash

    justified_epoch*: uint64 ##\
    ## Epoch of last justified beacon block

    justified_block_root*: Eth2Digest ##\
    ## Hash of last justified beacon block

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#attestationdata
  AttestationDataAndCustodyBit* = object
    data*: AttestationData
    custody_bit: bool

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#deposit
  Deposit* = object
    branch*: seq[Eth2Digest] ##\
    ## Branch in the deposit tree

    index*: uint64 ##\
    ## Index in the deposit tree

    deposit_data*: DepositData ##\
    ## Data

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#depositdata
  DepositData* = object
    amount*: uint64 ## Value in Gwei
    timestamp*: uint64 # Timestamp from deposit contract
    deposit_input*: DepositInput

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#depositinput
  DepositInput* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    randao_commitment*: Eth2Digest # Initial RANDAO commitment
    proof_of_possession*: ValidatorSig ##\
    ## BLS proof of possession (a BLS signature)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#exit
  Exit* = object
    # Minimum epoch for processing exit
    epoch*: uint64
    # Index of the exiting validator
    validator_index*: ValidatorIndex
    # Validator signature
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: uint64
    parent_root*: Eth2Digest ##\
    ##\ Root hash of the previous block

    state_root*: Eth2Digest ##\
    ##\ The state root, _after_ this block has been processed

    randao_reveal*: ValidatorSig ##\
    ## Proposer RANDAO reveal

    eth1_data*: Eth1Data

    signature*: ValidatorSig ##\
    ## Proposer signature

    body*: BeaconBlockBody

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    proposer_slashings*: seq[ProposerSlashing]
    attester_slashings*: seq[AttesterSlashing]
    attestations*: seq[Attestation]
    deposits*: seq[Deposit]
    exits*: seq[Exit]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#proposalsigneddata
  ProposalSignedData* = object
    slot*: uint64
    shard*: uint64 ##\
    ## Shard number (or `BEACON_CHAIN_SHARD_NUMBER` for beacon chain)
    block_root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#beaconstate
  BeaconState* = object
    slot*: uint64
    genesis_time*: uint64
    fork*: Fork ##\
    ## For versioning hard forks

    # Validator registry
    validator_registry*: seq[Validator]
    validator_balances*: seq[uint64] ##\
    ## Validator balances in Gwei!

    validator_registry_update_epoch*: uint64

    # TODO remove, not in spec anymore
    validator_registry_delta_chain_tip*: Eth2Digest ##\
    ## For light clients to easily track delta

    # Randomness and committees
    latest_randao_mixes*: array[LATEST_BLOCK_ROOTS_LENGTH.int, Eth2Digest]
    previous_epoch_start_shard*: uint64
    current_epoch_start_shard*: uint64
    previous_calculation_epoch*: EpochNumber
    current_calculation_epoch*: EpochNumber
    previous_epoch_seed*: Eth2Digest
    current_epoch_seed*: Eth2Digest

    # Finality
    previous_justified_epoch*: EpochNumber
    justified_epoch*: EpochNumber
    justification_bitfield*: uint64
    finalized_epoch*: EpochNumber

    # Recent state
    latest_crosslinks*: array[SHARD_COUNT, Crosslink]
    latest_block_roots*: array[LATEST_BLOCK_ROOTS_LENGTH.int, Eth2Digest] ##\
    ## Needed to process attestations, older to newer
    latest_index_roots*: array[LATEST_INDEX_ROOTS_LENGTH.int, Eth2Digest]

    latest_penalized_exit_balances*: seq[uint64] ##\
    ## Balances penalized in the current withdrawal period

    latest_attestations*: seq[PendingAttestation]
    batched_block_roots*: seq[Eth2Digest]

    latest_eth1_data*: Eth1Data
    eth1_data_votes*: seq[Eth1DataVote]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#validator
  Validator* = object
    pubkey*: ValidatorPubKey ##\
    ## BLS public key

    withdrawal_credentials*: Eth2Digest ##\
    ## Withdrawal credentials

    activation_epoch*: EpochNumber ##\
    ## Epoch when validator activated

    exit_epoch*: EpochNumber ##\
    ## Epoch when validator exited

    withdrawal_epoch*: EpochNumber ##\
    ## Epoch when validator withdrew

    penalized_epoch*: EpochNumber ##\
    ## Epoch when validator penalized

    status_flags*: uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#crosslink
  Crosslink* = object
    epoch*: uint64
    shard_block_root*: Eth2Digest ##\
    ## Shard chain block root

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#pendingattestation
  PendingAttestation* = object
    aggregation_bitfield*: seq[byte]          # Attester participation bitfield
    data*: AttestationData                    # Attestation data
    custody_bitfield*: seq[byte]              # Custody bitfield
    inclusion_slot*: uint64                   # Inclusion slot

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#fork
  Fork* = object
    previous_version*: uint64                     # Previous fork version
    current_version*: uint64                      # Current fork version
    epoch*: uint64                                # Fork epoch number

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#eth1data
  Eth1Data* = object
    deposit_root*: Eth2Digest ##\
    ## Data being voted for

    block_hash*: Eth2Digest ##\
    ## Block hash

  # https://github.com/ethereum/eth2.0-specs/blob/v0.1/specs/core/0_beacon-chain.md#eth1datavote
  Eth1DataVote* = object
    eth1_data*: Eth1Data
    vote_count*: uint64                           # Vote count

  ## TODO remove or otherwise conditional-compile this, since it's for light
  ## client but not in spec
  ValidatorRegistryDeltaBlock* = object
    latest_registry_delta_root*: Eth2Digest
    validator_index*: ValidatorIndex
    pubkey*: ValidatorPubKey
    slot*: uint64
    flag*: ValidatorSetDeltaFlags

  ## TODO remove or otherwise conditional-compile this, since it's for light
  ## client but not in spec
  ValidatorSetDeltaFlags* {.pure.} = enum
    Activation = 0
    Exit = 1

  # https://github.com/ethereum/eth2.0-specs/blob/dev/specs/core/0_beacon-chain.md#signature-domains
  SignatureDomain* {.pure.} = enum
    DOMAIN_DEPOSIT = 0
    DOMAIN_ATTESTATION = 1
    DOMAIN_PROPOSAL = 2
    DOMAIN_EXIT = 3
    DOMAIN_RANDAO = 4

  # TODO: not in spec
  CrosslinkCommittee* = tuple[committee: seq[ValidatorIndex], shard: uint64]

template epoch*(slot: int|uint64): auto =
  slot div EPOCH_LENGTH

when true:
  # TODO: Remove these once RLP serialization is no longer used
  import nimcrypto, eth/rlp, json_serialization
  export append, read, json_serialization

  proc append*(rlpWriter: var RlpWriter, value: ValidatorPubKey) =
    discard

  proc read*(rlp: var Rlp, T: type ValidatorPubKey): T {.inline.} =
    discard

  proc append*(rlpWriter: var RlpWriter, value: ValidatorIndex) =
    discard

  proc read*(rlp: var Rlp, T: type ValidatorIndex): T {.inline.} =
    discard

  proc append*(rlpWriter: var RlpWriter, value: ValidatorSig) =
    discard

  proc read*(rlp: var Rlp, T: type ValidatorSig): T {.inline.} =
    discard

export
  writeValue, readValue

