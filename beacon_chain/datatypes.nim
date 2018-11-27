# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# The latest version can be seen here:
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/beacon-chain.md
#
# How wrong the code is:
# https://github.com/ethereum/eth2.0-specs/compare/98312f40b5742de6aa73f24e6225ee68277c4614...master

import
  intsets, eth_common, math, stint, digest

import milagro_crypto
  # nimble install https://github.com/status-im/nim-milagro-crypto@#master
  # Defines
  #  - SigKey (private/secret key) (48 bytes - 384-bit)
  #  - Signature                   (48 bytes - 384-bit)
  #  - VerKey (public key)         (192 bytes)

const
  SHARD_COUNT*                              = 1024 # a constant referring to the number of shards
  DEPOSIT_SIZE*                             = 2^5  # You need to deposit 32 ETH to be a validator in Casper
  MIN_ONLINE_DEPOSIT_SIZE*                  = 2^4  # ETH
  GWEI_PER_ETH*                             = 10^9 # Gwei/ETH
  TARGET_COMMITTEE_SIZE*                    = 2^8  # validators
  SLOT_DURATION*                            = 6    # seconds
  CYCLE_LENGTH*                             = 64   # slots (~ 6 minutes)
  MIN_VALIDATOR_SET_CHANGE_INTERVAL*        = 2^8  # slots (~25 minutes)
  SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD* = 2^17 # slots (~9 days)
  MIN_ATTESTATION_INCLUSION_DELAY*          = 2^2  # slots (~25 minutes)
  SQRT_E_DROP_TIME*                         = 2^16 # slots (~12 days); amount of time it takes for the
                                                   # quadratic leak to cut deposits of non-participating
                                                   # validators by ~39.4%
  WITHDRAWALS_PER_CYCLE*                    = 2^2  # validators (5.2m ETH in ~6 months)
  MIN_WITHDRAWAL_PERIOD*                    = 2^13 # slots (~14 hours)
  DELETION_PERIOD*                          = 2^22 # slots (~290 days)
  COLLECTIVE_PENALTY_CALCULATION_PERIOD*    = 2^20 # slots (~2.4 months)
  SLASHING_WHISTLEBLOWER_REWARD_DENOMINATOR* = 2^9 # ?
  BASE_REWARD_QUOTIENT*                     = 2^15 # per-slot interest rate assuming all validators are
                                                   # participating, assuming total deposits of 1 ETH. It
                                                   # corresponds to ~3.88% annual interest assuming 10
                                                   # million participating ETH.
  MAX_VALIDATOR_CHURN_QUOTIENT*             = 2^5  # At most `1/MAX_VALIDATOR_CHURN_QUOTIENT` of the
                                                   # validators can change during each validator set
                                                   # change.
  POW_HASH_VOTING_PERIOD*                   = 2^10 # ?
  POW_CONTRACT_MERKLE_TREE_DEPTH*           = 2^5  #
  INITIAL_FORK_VERSION*                     = 0    # currently behaves like a constant

type
  # Alias
  BLSPublicKey* = VerKey
  BLSsig*       = Signature

  Uint24* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around

  SpecialRecord* = object
    kind*: SpecialRecordTypes                     # Kind
    data*: seq[byte]                              # Data

  BeaconBlock* = object
    slot*: uint64                                  # Slot number
    randao_reveal*: Eth2Digest                     # Proposer RANDAO reveal
    candidate_pow_receipt_root*: Eth2Digest        # Recent PoW chain reference (receipt root)
    ancestor_hashes*: seq[Eth2Digest]              # Skip list of previous beacon block hashes
                                                   # i'th item is most recent ancestor whose
                                                   # slot is a multiple of 2**i for
                                                   # i == 0, ..., 31
    state_root*: Eth2Digest                        # State root
    attestations*: seq[AttestationRecord]          # Attestations
    specials*: seq[SpecialRecord]                  # Specials (e.g. logouts, penalties)
    proposer_signature*: BLSSig                    # Proposer signature

  ProposalSignedData* = object
    fork_version*: uint64                         # Fork version
    slot*: uint64                                 # Slot number
    shard_id*: uint64                             # Shard ID (or `2**64 - 1` for beacon chain)
    block_hash*: Eth2Digest                       # Block hash

  AttestationSignedData* = object
    fork_version*: uint64                         # Fork version
    slot*: uint64                                 # Slot number
    shard*: uint16                                # Shard number
    parent_hashes*: seq[Eth2Digest]               # CYCLE_LENGTH parent hashes
    shard_block_hash*: Eth2Digest                 # Shard block hash
    last_crosslink_hash*: Eth2Digest              # Last crosslink hash
    shard_block_combined_data_root*: Eth2Digest
                                                  # Root of data between last hash and this one
    justified_slot*: uint64                       # Slot of last justified beacon block referenced in the attestation

  ShardAndCommittee* = object
    shard_id*: uint16                             # Shard number
    committee*: seq[Uint24]                       # Validator indices

  ShardReassignmentRecord* = object
    validator_index*: Uint24                      # Which validator to reassign
    shard*: uint16                                # To which shard
    slot*: uint64                                 # When

  CrosslinkRecord* = object
    slot*: uint64                                 # Slot number
    hash*: Eth2Digest                             # Shard chain block hash

  AttestationRecord* = object
    slot*: uint64                                  # Slot number
    shard*: uint16                                 # Shard number
    oblique_parent_hashes*: seq[Eth2Digest]
      # Beacon block hashes not part of the current chain, oldest to newest
    shard_block_hash*: Eth2Digest          # Shard block hash being attested to
    last_crosslink_hash*: Eth2Digest       # Last crosslink hash
    shard_block_combined_data_root*: Eth2Digest
                                                  # Root of data between last hash and this one
    attester_bitfield*: IntSet                    # Attester participation bitfield (1 bit per attester)
    justified_slot*: uint64                       # Slot of last justified beacon block
    justified_block_hash*: Eth2Digest             # Hash of last justified beacon block
    aggregate_sig*: BLSSig                        # BLS aggregate signature

  BeaconState* = object
    validator_set_change_slot*: uint64                     # Slot of last validator set change
    validators*: seq[ValidatorRecord]                      # List of validators
    crosslinks*: seq[CrosslinkRecord]                      # Most recent crosslink for each shard
    last_state_recalculation_slot*: uint64                 # Last cycle-boundary state recalculation
    last_finalized_slot*: uint64                           # Last finalized slot
    last_justified_slot*: uint64                           # Last justified slot
    justified_streak*: uint64                              # Number of consecutive justified slots
    shard_and_committee_for_slots*: array[2 * CYCLE_LENGTH, seq[ShardAndCommittee]] ## \
    ## Committee members and their assigned shard, per slot, covers 2 cycles
    ## worth of assignments
    persistent_committees*: seq[seq[ValidatorRecord]]      # Persistent shard committees
    persistent_committee_reassignments*: seq[ShardReassignmentRecord]
    next_shuffling_seed*: Eth2Digest                       # Randao seed used for next shuffling
    deposits_penalized_in_period*: uint32                  # Total deposits penalized in the given withdrawal period
    validator_set_delta_hash_chain*: Eth2Digest            # Hash chain of validator set changes (for light clients to easily track deltas)
    current_exit_seq*: uint64                              # Current sequence number for withdrawals
    genesis_time*: uint64                                  # Genesis time
    known_pow_receipt_root*: Eth2Digest                    # PoW chain reference
    candidate_pow_receipt_root*: Eth2Digest
    candidate_pow_receipt_root_votes*: Eth2Digest
    pre_fork_version*: uint32                              # Parameters relevant to hard forks / versioning.
    post_fork_version*: uint32                             # Should be updated only by hard forks.
    fork_slot_number*: uint64
    pending_attestations*: seq[AttestationRecord]          # Attestations not yet processed
    recent_block_hashes*: seq[Eth2Digest]                  # recent beacon block hashes needed to process attestations, older to newer
    randao_mix*: Eth2Digest                                # RANDAO state

  ValidatorRecord* = object
    pubkey*: BLSPublicKey                         # BLS public key
    withdrawal_shard*: uint16                     # Withdrawal shard number
    withdrawal_address*: EthAddress               # Withdrawal address
    randao_commitment*: Eth2Digest                # RANDAO commitment
    randao_last_change*: uint64                   # Slot the RANDAO commitment was last changed
    balance*: uint64                              # Balance in Gwei
    status*: ValidatorStatusCodes                 # Status code
    exit_slot*: uint64                            # Slot when validator exited (or 0)
    exit_seq*: uint64                             # Sequence number when validator exited (or 0)

  InitialValidator* = object
    pubkey*: BLSPublicKey
    proof_of_possession*: seq[byte]
    withdrawal_shard*: uint16
    withdrawal_address*: EthAddress
    randao_commitment*: Eth2Digest

  ValidatorStatusCodes* {.pure.} = enum
    PendingActivation = 0
    Active = 1
    PendingExit = 2
    PendingWithdraw = 3
    Withdrawn = 4
    Penalized = 127

  SpecialRecordTypes* {.pure.} = enum
    Logout = 0
    CasperSlashing = 1
    RandaoChange = 2

  ValidatorSetDeltaFlags* {.pure.} = enum
    Entry = 0
    Exit = 1

    # Note:
    # We use IntSet from Nim Standard library which are efficient sparse bitsets.
    # See: https://nim-lang.org/docs/intsets.html
    #
    # Future:
    #   IntSets stores the first 34 elements in an array[34, int] instead of a bitfield
    #   to avoid heap allocation in profiled common cases.
    #
    #   In Ethereum we probably always have over 34 attesters given the goal of decentralization.
    #   Allocating 8 * 34 = 272 bytes on the stack is wasteful, when this can be packed in just 8 bytes
    #   with room to spare.
    #
    #   Also, IntSets uses machine int size while we require int64 even on 32-bit platform.
