# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# In process of being updated as of spec from 2018-11-05
# https://github.com/ethereum/eth2.0-specs/tree/59f32978d489020770ae50e6d45450103445c6ad
#
# The latest version can be seen here:
# https://github.com/ethereum/eth2.0-specs/blob/master/specs/beacon-chain.md
#
# How wrong the code is:
# https://github.com/ethereum/eth2.0-specs/compare/59f32978d489020770ae50e6d45450103445c6ad...master

import
  intsets, eth_common, math, stint

import milagro_crypto
  # nimble install https://github.com/status-im/nim-milagro-crypto@#master
  # Defines
  #  - SigKey (private/secret key) (48 bytes - 384-bit)
  #  - Signature                   (48 bytes - 384-bit)
  #  - VerKey (public key)         (192 bytes)

type
  # Alias
  BLSPublicKey* = VerKey
  BLSsig*       = Signature

  Blake2_256_Digest* = Hash256           # TODO change to Blake2b-512[0 ..< 32] see https://github.com/status-im/nim-beacon-chain/issues/3
  Uint24* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around

  SpecialRecord* = object
    kind*: SpecialRecordTypes                     # Kind
    data*: seq[byte]                              # Data

  BeaconBlock* = object
    slot*: uint64                                 # Slot number
    randao_reveal*: Blake2_256_Digest             # Proposer RANDAO reveal
    pow_chain_reference*: Blake2_256_Digest       # Recent PoW chain reference (block hash)
    ancestor_hashes*: seq[Blake2_256_Digest]      # Skip list of previous beacon block hashes
                                                  # i'th item is most recent ancestor whose
                                                  # slot is a multiple of 2**i for
                                                  # i == 0, ..., 31
    active_state_root*: Blake2_256_Digest         # Hash of the active state
    crystallized_state_root*: Blake2_256_Digest   # Hash of the crystallized state
    attestations*: seq[AttestationRecord]         # Attestation votes
    parent_hash*: Blake2_256_Digest               # Hash of the parent block

  ShardAndCommittee* = object
    shard_id*: int16                              # The shard ID
    committee*: seq[Uint24]                       # Validator indices

  ShardReassignmentRecord* = object
    validator_index*: Uint24                      # Which validator to reassign
    shard*: uint16                                # To which shard
    slot*: uint64                                 # When

  ValidatorRecord* = object
    pubkey*: BLSPublicKey                         # BLS public key
    withdrawal_shard*: uint16                     # Withdrawal shard number
    withdrawal_address*: EthAddress               # Withdrawal address
    randao_commitment*: Blake2_256_Digest         # RANDAO commitment
    randao_last_change*: uint64                   # Slot the RANDAO commitment was last changed
    balance*: uint64                              # Balance in Gwei
    status*: uint8                                # Status code [used to be more enum-like]
    exit_slot*: uint64                            # Slot when validator exited (or 0)

  CrosslinkRecord* = object
    dynasty: int64                                # What dynasty the crosslink was submitted in
    slot: int64                                   # What slot
    hash: Blake2_256_Digest                       # The block hash

  AttestationRecord* = object
    slot*: uint64                                  # Slot number
    shard*: uint16                                 # Shard ID
    oblique_parent_hashes*: seq[Blake2_256_Digest]
      # Beacon block hashes not part of the current chain, oldest to newest
    shard_block_hash*: Blake2_256_Digest          # Shard block hash being attested to
    attester_bitfield*: IntSet                    # Attester participation bitfield (1 bit per attester)
    justified_slot*: uint64                       # Slot of last justified beacon block
    justified_block_hash: Blake2_256_Digest       # Hash of last justified beacon block
    aggregate_sig*: Signature                     # BLS aggregate signature

  AttestationSignedData* = object
    fork_version*: uint64                              # Fork version
    slot*: uint64                                      # Slot number
    shard*: uint16                                     # Shard number
    parent_hashes*: seq[Blake2_256_Digest]
      # CYCLE_LENGTH parent hashes
    shard_block_hash*: Blake2_256_Digest               # Shard block hash
    shard_block_combined_data_root*: Blake2_256_Digest # Root of data between last hash and this one
    justified_slot*: uint64                            # Slot of last justified beacon block referenced in the attestation

  BeaconState* = object
    validator_set_change_slot*: uint64                     # Slot of last validator set change
    validators*: seq[ValidatorRecord]                      # List of validators
    crosslinks*: seq[CrosslinkRecord]                      # Most recent crosslink for each shard
    last_state_recalculation_slot*: uint64                 # Last cycle-boundary state recalculation
    last_finalized_slot*: uint64                           # Last finalized slot
    last_justified_slot*: uint64                           # Last justified slot
    justified_streak*: uint64                              # Number of consecutive justified slots
    shard_and_committee_for_slots*: seq[ShardAndCommittee] # Committee members and their assigned shard, per slot
    persistent_committees*: Uint24                         # Persistent shard committees
    persistent_committee_reassignments*: seq[ShardReassignmentRecord]
    next_shuffling_seed*: Blake2_256_Digest                # Randao seed used for next shuffling
    deposits_penalized_in_period*: uint32                  # Total deposits penalized in the given withdrawal period
    validator_set_delta_hash_chain*: Blake2_256_Digest     # Hash chain of validator set changes (for light clients to easily track deltas)
    pre_fork_version*: uint32                              # Parameters relevant to hard forks / versioning.
    post_fork_version*: uint32                             # Should be updated only by hard forks.
    fork_slot_number*: uint64
    pending_attestations*: seq[AttestationRecord]          # Attestations not yet processed
    pending_specials*: seq[SpecialRecord]                  # Specials not yet been processed
    recent_block_hashes*: Blake2_256_Digest                # recent beacon block hashes needed to process attestations, older to newer
    randao_mix*: Blake2_256_Digest                         # RANDAO state

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


const
  SHARD_COUNT*                              = 1024 # a constant referring to the number of shards
  DEPOSIT_SIZE*                             = 2^5  # You need to deposit 32 ETH to be a validator in Casper
  SLOT_DURATION*                            = 16   # seconds
  CYCLE_LENGTH*                             = 64   # slots
  MIN_COMMITTEE_SIZE*                       = 2^7  # validators; 2018-11-05 version of spec also says:
                                                   # See a recommended `MIN_COMMITTEE_SIZE`  of 111 here
                                                   # https://vitalik.ca/files/Ithaca201807_Sharding.pdf).
  SQRT_E_DROP_TIME*                         = 2^16 # slots (~12 days); amount of time it takes for the
                                                   # quadratic leak to cut deposits of non-participating
                                                   # validators by ~39.4%
  BASE_REWARD_QUOTIENT*                     = 2^15 # per-slot interest rate assuming all validators are
                                                   # participating, assuming total deposits of 1 ETH. It
                                                   # corresponds to ~3.88% annual interest assuming 10
                                                   # million participating ETH.
  MIN_BALANCE*                              = 2^4  # ETH
  MIN_ONLINE_DEPOSIT_SIZE*                  = 2^4  # ETH
  GWEI_PER_ETH*                             = 10^9 # Gwei/ETH
  MIN_VALIDATOR_SET_CHANGE_INTERVAL*        = 2^8  # slots (~1.1 hours)
  RANDAO_SLOTS_PER_LAYER*                   = 2^12 # slots (~18 hours)
  WITHDRAWAL_PERIOD*                        = 2^19 # slots (~97 days)
  SHARD_PERSISTENT_COMMITTEE_CHANGE_PERIOD* = 2^16 # slots (~12 days)
  MAX_VALIDATOR_CHURN_QUOTIENT*             = 2^5  # At most `1/MAX_VALIDATOR_CHURN_QUOTIENT` of the
                                                   # validators can change during each validator set
                                                   # change.
  INITIAL_FORK_VERSION*                     = 0    # currently behaves like a constant
