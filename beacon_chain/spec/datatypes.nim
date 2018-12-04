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
# https://github.com/ethereum/eth2.0-specs/compare/2983e68f0305551083fac7fcf9330c1fc9da3411...master
#
# These datatypes are used as specifications for serialization - thus should not
# be altered outside of what the spec says. Likewise, they should not be made
# `ref` - this can be achieved by wrapping them in higher-level
# types / composition

import
  intsets, eth_common, math,
  ./crypto, ./digest

const
  SHARD_COUNT*                              = 1024 # a constant referring to the number of shards
  TARGET_COMMITTEE_SIZE*                    = 2^8  # validators
  MAX_ATTESTATIONS_PER_BLOCK*               = 2^7  # attestations
  MAX_DEPOSIT*                              = 2^5  # ETH
  MIN_BALANCE*                              = 2^4  # ETH
  POW_CONTRACT_MERKLE_TREE_DEPTH*           = 2^5  #
  INITIAL_FORK_VERSION*                     = 0    #
  INITIAL_SLOT_NUMBER*                      = 0    #
  GWEI_PER_ETH*                             = 10^9 # Gwei/ETH
  ZERO_HASH*                                = Eth2Digest()
  BEACON_CHAIN_SHARD_NUMBER*                = not 0'u64

  # Time constants
  SLOT_DURATION*                            = 6    # seconds
  MIN_ATTESTATION_INCLUSION_DELAY*          = 4    # slots (~25 minutes)
  EPOCH_LENGTH*                             = 64   # slots (~6.4 minutes)
  MIN_VALIDATOR_REGISTRY_CHANGE_INTERVAL*   = 2^8  # slots (~25.6 minutes)
  POW_RECEIPT_ROOT_VOTING_PERIOD*           = 2^10 # slots (~1.7 hours)
  SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD* = 2^17 # slots (~9 days)
  SQRT_E_DROP_TIME*                         = 2^17 # slots (~9 days); amount of time it takes for the
                                                   # quadratic leak to cut deposits of non-participating
                                                   # validators by ~39.4%
  COLLECTIVE_PENALTY_CALCULATION_PERIOD*    = 2^20 # slots (~2.4 months)
  DELETION_PERIOD*                          = 2^22 # slots (~290 days)

  # Quotients
  BASE_REWARD_QUOTIENT*                     = 2^11 # per-cycle interest rate assuming all validators are
                                                   # participating, assuming total deposits of 1 ETH. It
                                                   # corresponds to ~2.57% annual interest assuming 10
                                                   # million participating ETH.
  WHISTLEBLOWER_REWARD_QUOTIENT*            = 2^9  # ?
  INCLUDER_REWARD_QUOTIENT*                 = 2^3  #
  MAX_CHURN_QUOTIENT*                       = 2^5  # At most `1/MAX_VALIDATOR_CHURN_QUOTIENT` of the
                                                   # validators can change during each validator set
                                                   # change.

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
    proposer_signature*: ValidatorSig              # Proposer signature

  AttestationRecord* = object
    data*: AttestationData
    participation_bitfield*: seq[byte]             # Attester participation bitfield
    custody_bitfield*: seq[byte]                   # Proof of custody bitfield
    aggregate_sig*: ValidatorSig                   # BLS aggregate signature

  AttestationData* = object
    slot*: uint64                                 # Slot number
    shard*: uint64                                # Shard number
    beacon_block_hash*: Eth2Digest                # Hash of the block we're signing
    epoch_boundary_hash*: Eth2Digest              # Hash of the ancestor at the cycle boundary
    shard_block_hash*: Eth2Digest                 # Shard block hash being attested to
    latest_crosslink_hash*: Eth2Digest            # Last crosslink hash
    justified_slot*: uint64                       # Slot of last justified beacon block
    justified_block_hash*: Eth2Digest             # Hash of last justified beacon block

  ProposalSignedData* = object
    slot*: uint64                                 # Slot number
    shard*: uint64                                # Shard number (or `2**64 - 1` for beacon chain)
    block_hash*: Eth2Digest                       # Block hash

  SpecialRecord* = object
    kind*: SpecialRecordType                      # Kind
    data*: seq[byte]                              # Data

  BeaconState* = object
    # Validator registry
    validator_registry*: seq[ValidatorRecord]
    validator_registry_latest_change_slot*: uint64
    validator_registry_exit_count*: uint64
    validator_registry_delta_chain_tip*: Eth2Digest ##\
    ## For light clients to easily track delta

    # Randomness and committees
    randao_mix*: Eth2Digest                      # RANDAO state
    next_seed*: Eth2Digest                       # Randao seed used for next shuffling
    shard_and_committee_for_slots*: array[2 * EPOCH_LENGTH, seq[ShardAndCommittee]] ## \
    ## Committee members and their assigned shard, per slot, covers 2 cycles
    ## worth of assignments
    persistent_committees*: seq[seq[Uint24]]               # Persistent shard committees
    persistent_committee_reassignments*: seq[ShardReassignmentRecord]

    # Finality
    previous_justified_slot*: uint64
    justified_slot*: uint64
    justified_slot_bitfield*: uint64
    finalized_slot*: uint64

    latest_crosslinks*: array[SHARD_COUNT, CrosslinkRecord]
    latest_state_recalculation_slot*: uint64
    latest_block_hashes*: seq[Eth2Digest] ##\
    ## Needed to process attestations, older to newer
    latest_penalized_exit_balances*: seq[uint64] ##\
    ## Balances penalized in the current withdrawal period
    latest_attestations*: seq[PendingAttestationRecord]

    processed_pow_receipt_root*: Eth2Digest
    candidate_pow_receipt_roots*: seq[CandidatePoWReceiptRootRecord]

    genesis_time*: uint64
    fork_data*: ForkData ##\
    ## For versioning hard forks

  ValidatorRecord* = object
    pubkey*: ValidatorPubKey                      # Public key
    withdrawal_credentials*: Eth2Digest           # Withdrawal credentials
    randao_commitment*: Eth2Digest                # RANDAO commitment
    randao_skips*: uint64                         # Slot the proposer has skipped (ie. layers of RANDAO expected)
    balance*: uint64                              # Balance in Gwei
    status*: ValidatorStatusCodes                 # Status code
    latest_status_change_slot*: uint64            # Slot when validator last changed status (or 0)
    exit_count*: uint64                           # Exit counter when validator exited (or 0)

  CrosslinkRecord* = object
    slot*: uint64                                 # Slot number
    shard_block_hash*: Eth2Digest                 # Shard chain block hash

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
    fork_slot*: uint64                            # Fork slot number

  PendingAttestationRecord* = object
    data*: AttestationData                        # Signed data
    participation_bitfield*: seq[byte]            # Attester participation bitfield
    custody_bitfield*: seq[byte]                  # Proof of custody bitfield
    slot_included*: uint64                        # Slot in which it was included

  ValidatorStatusCodes* {.pure.} = enum
    PENDING_ACTIVATION = 0
    ACTIVE = 1
    EXITED_WITHOUT_PENALTY = 2
    EXITED_WITH_PENALTY = 3
    PENDING_EXIT = 29                             # https://github.com/ethereum/eth2.0-specs/issues/216

  SpecialRecordType* {.pure.} = enum
    Logout = 0
    CasperSlashing = 1
    RandaoChange = 2
    DepositProof = 3

  ValidatorSetDeltaFlags* {.pure.} = enum
    Activation = 0
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

when true:
  # TODO: Remove these once RLP serialization is no longer used
  import nimcrypto, rlp
  export append, read

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

