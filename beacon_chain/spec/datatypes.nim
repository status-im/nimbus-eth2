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
# https://github.com/ethereum/eth2.0-specs/compare/126a7abfa86448091a0e037f52966b6a9531a857...master

import
  intsets, eth_common, math,
  ./crypto, ./digest

const
  SHARD_COUNT*                              = 1024 # a constant referring to the number of shards
  DEPOSIT_SIZE*                             = 2^5  # You need to deposit 32 ETH to be a validator in Casper
  MIN_TOPUP_SIZE*                           = 1    # ETH
  MIN_ONLINE_DEPOSIT_SIZE*                  = 2^4  # ETH
  GWEI_PER_ETH*                             = 10^9 # Gwei/ETH
  DEPOSITS_FOR_CHAIN_START*                 = 2^14 # deposits
  TARGET_COMMITTEE_SIZE*                    = 2^8  # validators
  SLOT_DURATION*                            = 6    # seconds
  CYCLE_LENGTH*                             = 64   # slots (~ 6 minutes)
  MIN_VALIDATOR_SET_CHANGE_INTERVAL*        = 2^8  # slots (~25 minutes)
  SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD* = 2^17 # slots (~9 days)
  MIN_ATTESTATION_INCLUSION_DELAY*          = 4    # slots (~25 minutes)
  SQRT_E_DROP_TIME*                         = 2^9  # slots (~9 days); amount of time it takes for the
                                                   # quadratic leak to cut deposits of non-participating
                                                   # validators by ~39.4%
  WITHDRAWALS_PER_CYCLE*                    = 2^2  # validators (5.2m ETH in ~6 months)
  MIN_WITHDRAWAL_PERIOD*                    = 2^13 # slots (~14 hours)
  DELETION_PERIOD*                          = 2^22 # slots (~290 days)
  COLLECTIVE_PENALTY_CALCULATION_PERIOD*    = 2^20 # slots (~2.4 months)
  POW_RECEIPT_ROOT_VOTING_PERIOD*           = 2^10 # slots (~1.7 hours)
  SLASHING_WHISTLEBLOWER_REWARD_DENOMINATOR* = 2^9 # ?
  BASE_REWARD_QUOTIENT*                     = 2^11 # per-cycle interest rate assuming all validators are
                                                   # participating, assuming total deposits of 1 ETH. It
                                                   # corresponds to ~2.57% annual interest assuming 10
                                                   # million participating ETH.
  MAX_VALIDATOR_CHURN_QUOTIENT*             = 2^5  # At most `1/MAX_VALIDATOR_CHURN_QUOTIENT` of the
                                                   # validators can change during each validator set
                                                   # change.
  POW_CONTRACT_MERKLE_TREE_DEPTH*           = 2^5  #
  MAX_ATTESTATION_COUNT*                    = 2^7  #
  INITIAL_FORK_VERSION*                     = 0    #

type
  Uint24* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around

  BeaconBlock* = object
    slot*: uint64                                  # Slot number
    randao_reveal*: Eth2Digest                     # Proposer RANDAO reveal
    candidate_pow_receipt_root*: Eth2Digest        # Recent PoW receipt root
    ancestor_hashes*: seq[Eth2Digest]              # Skip list of previous beacon block hashes
                                                   # i'th item is most recent ancestor whose
                                                   # slot is a multiple of 2**i for
                                                   # i == 0, ..., 31
    state_root*: Eth2Digest                        # State root
    attestations*: seq[AttestationRecord]          # Attestations
    specials*: seq[SpecialRecord]                  # Specials (e.g. logouts, penalties)
    proposer_signature*: Eth2Signature             # Proposer signature

  AttestationRecord* = object
    data*: AttestationSignedData                   #
    attester_bitfield*: seq[byte]                  # Attester participation bitfield
    poc_bitfield*: seq[byte]                       # Proof of custody bitfield
    aggregate_sig*: Eth2Signature                  # BLS aggregate signature

  AttestationSignedData* = object
    slot*: uint64                                 # Slot number
    shard*: uint64                                # Shard number
    block_hash*: Eth2Digest                       # Hash of the block we're signing
    cycle_boundary_hash*: Eth2Digest              # Hash of the ancestor at the cycle boundary
    shard_block_hash*: Eth2Digest                 # Shard block hash being attested to
    last_crosslink_hash*: Eth2Digest              # Last crosslink hash
    justified_slot*: uint64                       # Slot of last justified beacon block
    justified_block_hash*: Eth2Digest             # Hash of last justified beacon block

  ProposalSignedData* = object
    slot*: uint64                                 # Slot number
    shard*: uint64                                # Shard number (or `2**64 - 1` for beacon chain)
    block_hash*: Eth2Digest                       # Block hash

  SpecialRecord* = object
    kind*: SpecialRecordTypes                     # Kind
    data*: seq[byte]                              # Data

  BeaconState* = object
    validator_set_change_slot*: uint64                     # Slot of last validator set change
    validators*: seq[ValidatorRecord]                      # List of validators
    crosslinks*: seq[CrosslinkRecord]                      # Most recent crosslink for each shard
    last_state_recalculation_slot*: uint64                 # Last cycle-boundary state recalculation
    last_finalized_slot*: uint64                           # Last finalized slot
    justification_source*: uint64                          # Justification source
    prev_cycle_justification_source*: uint64               #
    justified_slot_bitfield*: uint64                       # Recent justified slot bitmask
    shard_and_committee_for_slots*: array[2 * CYCLE_LENGTH, seq[ShardAndCommittee]] ## \
    ## Committee members and their assigned shard, per slot, covers 2 cycles
    ## worth of assignments
    persistent_committees*: seq[seq[Uint24]]               # Persistent shard committees
    persistent_committee_reassignments*: seq[ShardReassignmentRecord]
    next_shuffling_seed*: Eth2Digest                       # Randao seed used for next shuffling
    deposits_penalized_in_period*: uint32                  # Total deposits penalized in the given withdrawal period
    validator_set_delta_hash_chain*: Eth2Digest            # Hash chain of validator set changes (for light clients to easily track deltas)
    current_exit_seq*: uint64                              # Current sequence number for withdrawals
    genesis_time*: uint64                                  # Genesis time
    candidate_pow_receipt_root*: Eth2Digest                # PoW receipt root
    candidate_pow_receipt_roots*: seq[CandidatePoWReceiptRootRecord] #
    fork_data*: ForkData                                   # Parameters relevant to hard forks / versioning.
                                                           # Should be updated only by hard forks.
    pending_attestations*: seq[AttestationRecord]          # Attestations not yet processed
    recent_block_hashes*: seq[Eth2Digest]                  # recent beacon block hashes needed to process attestations, older to newer
    randao_mix*: Eth2Digest                                # RANDAO state

  ValidatorRecord* = object
    pubkey*: Eth2PublicKey                        # Public key
    withdrawal_credentials*: Eth2Digest           # Withdrawal credentials
    randao_commitment*: Eth2Digest                # RANDAO commitment
    randao_skips*: uint64                         # Slot the proposer has skipped (ie. layers of RANDAO expected)
    balance*: uint64                              # Balance in Gwei
    status*: ValidatorStatusCodes                 # Status code
    last_status_change_slot*: uint64              # Slot when validator last changed status (or 0)
    exit_seq*: uint64                             # Sequence number when validator exited (or 0)

  CrosslinkRecord* = object
    slot*: uint64                                 # Slot number
    hash*: Eth2Digest                             # Shard chain block hash

  ShardAndCommittee* = object
    shard*: uint64                                # Shard number
    committee*: seq[Uint24]                       # Validator indices

  ShardReassignmentRecord* = object
    validator_index*: Uint24                      # Which validator to reassign
    shard*: uint64                                # To which shard
    slot*: uint64                                 # When

  CandidatePoWReceiptRootRecord* = object
    candidate_pow_receipt_root*: Eth2Digest       # Candidate PoW receipt root
    votes*: uint64                                # Vote count

  ForkData* = object
    pre_fork_version*: uint64                     # Previous fork version
    post_fork_version*: uint64                    # Post fork version
    fork_slot_number*: uint64                     # Fork slot number

  ProcessedAttestation* = object
    data*: AttestationSignedData                  # Signed data
    attester_bitfield*: seq[byte]                 # Attester participation bitfield (2 bits per attester)
    poc_bitfield*: seq[byte]                      # Proof of custody bitfield
    slot_included*: uint64                        # Slot in which it was included

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
