# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import intsets, stint, eth_common

type
  AttestationVote* = object
    # Implementation pending https://ethresear.ch/t/implementations-of-proof-of-concept-beacon-chains/2509/5?u=mratsim

  Keccak256_Digest* = distinct Hash256
  Blake2_256_Digest* = distinct Hash256

  BeaconBlock* = object
    parentHash*: Keccak256_Digest             # Hash of the parent block
    slotNumber*: int64                        # Slot number (for the PoS mechanism)
    randaoReveal*: Keccak256_Digest           # Randao commitment reveal
    attestationVotes*: seq[AttestationVote]   # Attestation votes
    mainChainRef*: Keccak256_Digest           # Reference to main chain block
    activeStatehash*: Blake2_256_Digest       # Hash of the active state
    crystallizedStateHash*: Blake2_256_Digest # Hash of the crystallized state

  ActiveState* = IntSet
    # ## Spec
    # attestation_count: int64
    # attester_bitfields: seq[byte]

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

  CrystallizedState* = object
    activeValidators: seq[ValidatorRecord] # List of active validators
    queuedValidators: seq[ValidatorRecord] # List of joined but not yet inducted validators
    exitedValidators: seq[ValidatorRecord] # List of removed validators pending withdrawal
    curEpochShuffling: seq[int32] #int24   # The permutation of validators used to determine who cross-links what shard in this epoch
    currentEpoch: int64                    # The current epoch
    lastJustifiedEpoch: int64              # The last justified epoch
    lastFinalizedEpoch: int64              # The last finalized epoch
    dynasty: int64                         # The current dynasty
    next_shard: int16                      # The next shard that cross-linking assignment will start from
    currentCheckpoint: Keccak256_Digest    # The current FFG checkpoint
    crosslinkRecords: seq[CrosslinkRecord] # Records about the most recent crosslink `for each shard
    totalDeposits: Int256                  # Total balance of deposits
    crosslinkSeed: Keccak256_Digest        # Used to select the committees for each shard
    crosslinkSeedLastReset: int64          # Last epoch the crosslink seed was reset

  BLSPublicKey = object
    # Stub for BLS signature
    data: array[32, byte]

  ValidatorRecord* = object
    pubkey: BLSPublicKey                   # The validator's public key
    withdrawalShard: int16                 # What shard the validator's balance will be sent to after withdrawal
    withdrawalAddress: EthAddress          # And what address
    randaoCommitment: Keccak256_Digest     # The validator's current RANDAO beacon commitment
    balance: int64                         # Current balance
    switchDynasty: int64                   # Dynasty where the validator can (be inducted | be removed | withdraw their balance)

  CrosslinkRecord* = object
    epoch: int64                           # What epoch the crosslink was submitted in
    hash: Keccak256_Digest                 # The block hash
