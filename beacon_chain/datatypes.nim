# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import intsets, eth_common, math

# Implementation based on WIP spec https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ?view
# ⚠ Spec is updated very often, implementation might quickly be outdated

type
  Keccak256_Digest* =  Hash256  # TODO, previously Keccak256 fields used the "bytes" type
  Blake2_256_Digest* = Hash256  # while Blake2 used hash32, but latest spec changed everything to hash32
  Uint24* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around

  BeaconBlock* = object
    parent_hash*: Keccak256_Digest                # Hash of the parent block
    slot_number*: int64                           # Slot number (for the PoS mechanism)
    randao_reveal*: Keccak256_Digest              # Randao commitment reveal
    attestations*: seq[AttestationRecord]         # Attestation votes
    pow_chain_ref*: Keccak256_Digest              # Reference to main chain block
    active_state_root*: Blake2_256_Digest         # Hash of the active state
    crystallized_state_root*: Blake2_256_Digest   # Hash of the crystallized state

  ActiveState* = object
    pending_attestations*: seq[AttestationRecord] # Attestations that have not yet been processed
    recent_block_hashes*: seq[Keccak256_Digest]   # Most recent 2 * CYCLE_LENGTH block hashes, older to newer

  CrystallizedState* = object
    validators*: seq[ValidatorRecord]             # List of active validators
    last_state_recalc*: int64                     # Last CrystallizedState recalculation
    indices_for_heights*: seq[seq[ShardAndCommittee]]
      # What active validators are part of the attester set
      # at what height, and in what shard. Starts at slot
      # last_state_recalc - CYCLE_LENGTH
    last_justified_slot*: int64                   # The last justified slot
    justified_streak*: int16                      # Number of consecutive justified slots ending at this one
    last_finalized_slot*: int64                   # The last finalized slot
    current_dynasty*: int64                       # The current dynasty
    crosslinking_start_shard*: int16              # The next shard that cross-linking assignment will start from
    crosslink_records*: seq[CrosslinkRecord]      # Records about the most recent crosslink for each shard
    total_deposits*: Int256                       # Total balance of deposits
    dynasty_seed*: Keccak256_Digest               # Used to select the committees for each shard
    dynasty_seed_last_reset*: int64               # Last epoch the crosslink seed was reset

  ShardAndCommittee* = object
    shard_id*: int16                              # The shard ID
    committee*: seq[Uint24]                       # Validator indices

  ValidatorRecord* = object
    pubkey*: BLSPublicKey                         # The validator's public key
    withdrawal_shard*: int16                      # What shard the validator's balance will be sent to after withdrawal
    withdrawal_address*: EthAddress               # And what address
    randao_commitment*: Keccak256_Digest          # The validator's current RANDAO beacon commitment
    balance*: int64                               # Current balance
    start_dynasty*: int64                         # Dynasty where the validator is inducted
    end_dynasty*: int64                           # Dynasty where the validator leaves

  CrosslinkRecord* = object
    dynasty: int64                                # What dynasty the crosslink was submitted in
    hash: Keccak256_Digest                        # The block hash

  BLSPublicKey = object
    # Stub for BLS signature
    data: array[32, byte]

  AttestationRecord* = object
    slot*: int64                                  # Slot number
    shard_id*: int16                              # Shard ID
    oblique_parent_hashes*: seq[Keccak256_Digest]
      # List of block hashes that this signature is signing over that
      # are NOT part of the current chain, in order of oldest to newest
    shard_block_hash*: Keccak256_Digest           # Block hash in the in the shard that we are attesting to
    attester_bitfield*: IntSet                    # Who is participating
    aggregateSig*: seq[BLSPublicKey]              # The actual signature
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
  SHARD_COUNT*         = 1024 # a constant referring to the number of shards
  DEPOSITE_SIZE*       = 32   # You need to deposit 32 ETH to be a validator in Casper
  MAX_VALIDATOR_COUNT* = 2^22 # 4_194_304, this means that ~132M ETH can stake at the same time (= MaxValidator Count * DepositSize)
  SLOT_DURATION*       = 8    # seconds
  CYCLE_LENGTH*        = 64   # slots
  MIN_COMMITTEE_SIZE*  = 128  # (rationale: see recommended minimum 111 here https://vitalik.ca/files/Ithaca201807_Sharding.pdf)
