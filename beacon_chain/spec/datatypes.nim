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
# The latest version can be seen here:
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/beacon-chain.md
#
# How wrong the code is:
# https://github.com/ethereum/eth2.0-specs/compare/8116562049ed80ad1823dd62e98a7483ddf1546c...master
#
# These datatypes are used as specifications for serialization - thus should not
# be altered outside of what the spec says. Likewise, they should not be made
# `ref` - this can be achieved by wrapping them in higher-level
# types / composition

import
  eth_common, math,
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

  EJECTION_BALANCE* = 2'u64^4 ##\
  ## Once the balance of a validator drops below this, it will be ejected from
  ## the validator pool

  MAX_BALANCE_CHURN_QUOTIENT* = 2^5 ##\
  ## At most `1/MAX_BALANCE_CHURN_QUOTIENT` of the validators can change during
  ## each validator registry change.

  GWEI_PER_ETH* = 10'u64^9 # Gwei/ETH

  BEACON_CHAIN_SHARD_NUMBER* = not 0'u64 # 2^64 - 1 in spec

  BLS_WITHDRAWAL_PREFIX_BYTE* = 0'u8

  MAX_CASPER_VOTES* = 2^10
  LATEST_BLOCK_ROOTS_LENGTH* = 2'u64^13
  LATEST_RANDAO_MIXES_LENGTH* = 2'u64^13

  DEPOSIT_CONTRACT_TREE_DEPTH* = 2^5

  MIN_DEPOSIT* = 2'u64^0 ##\
  ## Minimum amounth of ETH that can be deposited in one call - deposits can
  ## be used either to top up an existing validator or commit to a new one
  MAX_DEPOSIT* = 2'u64^5 ##\
  ## Maximum amounth of ETH that can be deposited in one call

  # Initial values

  INITIAL_FORK_VERSION* = 0'u64
  INITIAL_SLOT_NUMBER* = 0'u64
  ZERO_HASH* = Eth2Digest()

  # Time constants
  SLOT_DURATION* = 6 ## \
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

  EPOCH_LENGTH* = 64 ##\
  ## (~6.4 minutes)
  ## slots that make up an epoch, at the end of which more heavy
  ## processing is done

  POW_RECEIPT_ROOT_VOTING_PERIOD* = 2'u64^10 ##\
  ## slots (~1.7 hours)

  SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD* = 2'u64^17 ##\
  ## slots (~9 days)

  COLLECTIVE_PENALTY_CALCULATION_PERIOD* = 2'u64^20 ##\
  ## slots (~73 days)

  ZERO_BALANCE_VALIDATOR_TTL* = 2'u64^22 ##\
  ## slots (~291 days)

  # Quotients
  BASE_REWARD_QUOTIENT* = 2'u64^10 ##\
  ## The `BASE_REWARD_QUOTIENT` parameter dictates the per-epoch reward. It
  ## corresponds to ~2.54% annual interest assuming 10 million participating
  ## ETH in every epoch.
  WHISTLEBLOWER_REWARD_QUOTIENT* = 2'u64^9
  INCLUDER_REWARD_QUOTIENT* = 2'u64^3
  INACTIVITY_PENALTY_QUOTIENT* = 2'u64^24

  MAX_PROPOSER_SLASHINGS* = 2^4
  MAX_CASPER_SLASHINGS* = 2^4
  MAX_ATTESTATIONS* = 2^7
  MAX_DEPOSITS* = 2^4
  MAX_EXITS* = 2^4

type
  Uint24* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around

  # https://github.com/ethereum/eth2.0-specs/blob/master/specs/core/0_beacon-chain.md#data-structures
  ProposerSlashing* = object
    proposer_index*: Uint24
    proposal_data_1*: ProposalSignedData
    proposal_signature_1*: ValidatorSig
    proposal_data_2*: ProposalSignedData
    proposal_signature_2*: ValidatorSig

  CasperSlashing* = object
    slashable_vote_data_1*: SlashableVoteData
    slashable_vote_data_2*: SlashableVoteData

  SlashableVoteData* = object
    aggregate_signature_poc_0_indices*: seq[Uint24] ##\
    ## Proof-of-custody indices (0 bits)

    aggregate_signature_poc_1_indices*: seq[Uint24] ##\
    ## Proof-of-custody indices (1 bits)

    data*: AttestationData
    aggregate_signature*: ValidatorSig

  Attestation* = object
    data*: AttestationData
    participation_bitfield*: seq[byte] ##\
    ## The attesters that are represented in the aggregate signature - each
    ## bit represents an index in `ShardCommittee.committee`

    custody_bitfield*: seq[byte] ##\
    ## Proof of custody - Phase 1
    aggregate_signature*: ValidatorSig ##\
    ## Aggregate signature of the validators in `custody_bitfield`

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

    justified_slot*: uint64 ##\
    ## Slot of last justified beacon block

    justified_block_root*: Eth2Digest ##\
    ## Hash of last justified beacon block

  AttestationDataAndCustodyBit* = object
    data*: AttestationData
    poc_bit: bool

  Deposit* = object
    merkle_branch*: seq[Eth2Digest] ##\
    ## Receipt Merkle branch

    merkle_tree_index*: uint64

    ## Deposit data
    deposit_data*: DepositData

  DepositData* = object
    deposit_input*: DepositInput
    value*: uint64 ## Value in Gwei
    timestamp*: uint64 # Timestamp from deposit contract

  DepositInput* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    randao_commitment*: Eth2Digest # Initial RANDAO commitment
    poc_commitment*: Eth2Digest
    proof_of_possession*: ValidatorSig ##\
    ## BLS proof of possession (a BLS signature)

  Exit* = object
    # Minimum slot for processing exit
    slot*: uint64
    # Index of the exiting validator
    validator_index*: Uint24
    # Validator signature
    signature*: ValidatorSig

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

    randao_reveal*: Eth2Digest ##\
    ## Proposer RANDAO reveal

    candidate_pow_receipt_root*: Eth2Digest

    signature*: ValidatorSig ##\
    ## Proposer signature

    body*: BeaconBlockBody

  BeaconBlockBody* = object
    proposer_slashings*: seq[ProposerSlashing]
    casper_slashings*: seq[CasperSlashing]
    attestations*: seq[Attestation]
    poc_seed_changes*: seq[ProofOfCustodySeedChange]
    poc_challenges*: seq[ProofOfCustodyChallenge]
    poc_responses*: seq[ProofOfCustodyResponse]
    deposits*: seq[Deposit]
    exits*: seq[Exit]

  # Phase1:
  ProofOfCustodySeedChange* = object
  ProofOfCustodyChallenge* = object
  ProofOfCustodyResponse* = object

  ProposalSignedData* = object
    slot*: uint64
    shard*: uint64 ##\
    ## Shard number (or `BEACON_CHAIN_SHARD_NUMBER` for beacon chain)
    block_root*: Eth2Digest

  BeaconState* = object
    slot*: uint64
    genesis_time*: uint64
    fork_data*: ForkData ##\
    ## For versioning hard forks

    # Validator registry
    validator_registry*: seq[ValidatorRecord]
    validator_balances*: seq[uint64] ##\
    ## Validator balances in Gwei!

    validator_registry_latest_change_slot*: uint64
    validator_registry_exit_count*: uint64
    validator_registry_delta_chain_tip*: Eth2Digest ##\
    ## For light clients to easily track delta

    # Randomness and committees
    latest_randao_mixes*: array[LATEST_BLOCK_ROOTS_LENGTH.int, Eth2Digest]
    latest_vdf_outputs*: array[
      (LATEST_RANDAO_MIXES_LENGTH div EPOCH_LENGTH).int, Eth2Digest]

    shard_committees_at_slots*: array[2 * EPOCH_LENGTH, seq[ShardCommittee]] ## \
    ## Committee members and their assigned shard, per slot, covers 2 cycles
    ## worth of assignments

    persistent_committees*: seq[seq[Uint24]]
    persistent_committee_reassignments*: seq[ShardReassignmentRecord]

    poc_challenges*: seq[ProofOfCustodyChallenge]

    # Finality
    previous_justified_slot*: uint64
    justified_slot*: uint64
    justification_bitfield*: uint64
    finalized_slot*: uint64

    latest_crosslinks*: array[SHARD_COUNT, CrosslinkRecord]
    latest_block_roots*: array[LATEST_BLOCK_ROOTS_LENGTH.int, Eth2Digest] ##\
    ## Needed to process attestations, older to newer

    latest_penalized_exit_balances*: seq[uint64] ##\
    ## Balances penalized in the current withdrawal period

    latest_attestations*: seq[PendingAttestationRecord]
    batched_block_roots*: seq[Eth2Digest]

    processed_pow_receipt_root*: Eth2Digest
    candidate_pow_receipt_roots*: seq[CandidatePoWReceiptRootRecord]

  ValidatorRecord* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    randao_commitment*: Eth2Digest ##\
    ## RANDAO commitment created by repeatedly taking the hash of a secret value
    ## so as to create "onion layers" around it. For every block that a
    ## validator proposes, one level of the onion is peeled. See:
    ## * https://ethresear.ch/t/rng-exploitability-analysis-assuming-pure-randao-based-main-chain/1825
    ## * repeat_hash
    ## * processRandaoReveal

    randao_layers*: uint64 ##\
    ## Number of proposals the proposer missed, and thus the number of times to
    ## apply hash function to randao reveal

    status*: ValidatorStatusCodes
    latest_status_change_slot*: uint64 ##\
    ## Slot when validator last changed status (or 0)

    exit_count*: uint64 ##\
    ## Exit counter when validator exited (or 0)

    poc_commitment*: Eth2Digest

    last_poc_change_slot*: uint64
    second_last_poc_change_slot*: uint64

  CrosslinkRecord* = object
    slot*: uint64
    shard_block_root*: Eth2Digest ##\
    ## Shard chain block root

  ShardCommittee* = object
    shard*: uint64
    committee*: seq[Uint24] ##\
    ## Committe participants that get to attest to blocks on this shard -
    ## indices into BeaconState.validator_registry

    total_validator_count*: uint64 ##\
    ## Total validator count (for proofs of custody)

  ShardReassignmentRecord* = object
    validator_index*: Uint24 ##\
    ## Which validator to reassign

    shard*: uint64 ##\
    ## To which shard

    slot*: uint64 ##\
    ## When

  CandidatePoWReceiptRootRecord* = object
    candidate_pow_receipt_root*: Eth2Digest       # Candidate PoW receipt root
    vote_count*: uint64                           # Vote count

  PendingAttestationRecord* = object
    data*: AttestationData                        # Signed data
    participation_bitfield*: seq[byte]            # Attester participation bitfield
    custody_bitfield*: seq[byte]                  # Proof of custody bitfield
    slot_included*: uint64                        # Slot in which it was included

  ForkData* = object
    pre_fork_version*: uint64                     # Previous fork version
    post_fork_version*: uint64                    # Post fork version
    fork_slot*: uint64                            # Fork slot number

  ValidatorRegistryDeltaBlock* = object
    latest_registry_delta_root*: Eth2Digest
    validator_index*: Uint24
    pubkey*: ValidatorPubKey
    flag*: ValidatorSetDeltaFlags

  ValidatorStatusCodes* {.pure.} = enum
    PENDING_ACTIVATION = 0
    ACTIVE = 1
    ACTIVE_PENDING_EXIT = 2
    EXITED_WITHOUT_PENALTY = 3
    EXITED_WITH_PENALTY = 4

  ValidatorSetDeltaFlags* {.pure.} = enum
    Activation = 0
    Exit = 1

  SignatureDomain* {.pure.} = enum
    DOMAIN_DEPOSIT = 0
    DOMAIN_ATTESTATION = 1
    DOMAIN_PROPOSAL = 2
    DOMAIN_EXIT = 3

when true:
  # TODO: Remove these once RLP serialization is no longer used
  import nimcrypto, rlp, json_serialization
  export append, read, json_serialization

  proc append*(rlpWriter: var RlpWriter, value: ValidatorPubKey) =
    discard

  proc read*(rlp: var Rlp, T: type ValidatorPubKey): T {.inline.} =
    discard

  proc append*(rlpWriter: var RlpWriter, value: Uint24) =
    discard

  proc read*(rlp: var Rlp, T: type Uint24): T {.inline.} =
    discard

  proc append*(rlpWriter: var RlpWriter, value: ValidatorSig) =
    discard

  proc read*(rlp: var Rlp, T: type ValidatorSig): T {.inline.} =
    discard

export
  writeValue, readValue

