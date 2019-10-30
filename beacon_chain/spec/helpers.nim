# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Uncategorized helper functions from the spec

import
  # Standard lib
  sequtils, math, endians,
  # Third-party
  blscurve, # defines Domain
  # Internal
  ./datatypes, ./digest

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.0/specs/core/0_beacon-chain.md#integer_squareroot
func integer_squareroot*(n: SomeInteger): SomeInteger =
  # Return the largest integer ``x`` such that ``x**2 <= n``.
  doAssert n >= 0'u64

  var
    x = n
    y = (x + 1) div 2
  while y < x:
    x = y
    y = (x + n div x) div 2
  x

# TODO reuse as necessary/useful for merkle proof building
func merkle_root*(values: openArray[Eth2Digest]): Eth2Digest =
  ## Merkleize ``values`` (where ``len(values)`` is a power of two) and return
  ## the Merkle root.
  ## https://crypto.stackexchange.com/questions/43430/what-is-the-reason-to-separate-domains-in-the-internal-hash-algorithm-of-a-merkl
  let num_values = len(values)

  # Simplifies boundary conditions
  doAssert is_power_of_two(num_values)
  doAssert num_values >= 2
  doAssert num_values mod 2 == 0

  # TODO reverse ``o`` order and use newSeqWith to avoid pointless zero-filling.
  var o = repeat(ZERO_HASH, len(values))
  var hash_buffer: array[2*32, byte]

  # These ``o`` indices get filled from ``values``.
  let highest_internally_filled_index = (num_values div 2) - 1
  doAssert (highest_internally_filled_index + 1) * 2 >= num_values

  for i in countdown(num_values-1, highest_internally_filled_index + 1):
    hash_buffer[0..31] = values[i*2 - num_values].data
    hash_buffer[32..63] = values[i*2+1 - num_values].data
    o[i] = eth2hash(hash_buffer)

  ## These ``o`` indices get filled from other ``o`` indices.
  doAssert highest_internally_filled_index * 2 + 1 < num_values

  for i in countdown(highest_internally_filled_index, 1):
    hash_buffer[0..31] = o[i*2].data
    hash_buffer[32..63] = o[i*2+1].data
    o[i] = eth2hash(hash_buffer)

  o[1]

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.0/specs/core/0_beacon-chain.md#compute_epoch_at_slot
func compute_epoch_at_slot*(slot: Slot|uint64): Epoch =
  # Return the epoch number of the given ``slot``.
  (slot div SLOTS_PER_EPOCH).Epoch

template epoch*(slot: Slot): Epoch =
  compute_epoch_at_slot(slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.0/specs/core/0_beacon-chain.md#compute_start_slot_at_epoch
func compute_start_slot_at_epoch*(epoch: Epoch): Slot =
  # Return the start slot of ``epoch``.
  (epoch * SLOTS_PER_EPOCH).Slot

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.0/specs/core/0_beacon-chain.md#is_active_validator
func is_active_validator*(validator: Validator, epoch: Epoch): bool =
  ### Check if ``validator`` is active
  validator.activation_epoch <= epoch and epoch < validator.exit_epoch

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.0/specs/core/0_beacon-chain.md#get_active_validator_indices
func get_active_validator_indices*(state: BeaconState, epoch: Epoch):
    seq[ValidatorIndex] =
  # Return the sequence of active validator indices at ``epoch``.
  for idx, val in state.validators:
    if is_active_validator(val, epoch):
      result.add idx.ValidatorIndex

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_beacon-chain.md#get_committee_count
func get_committee_count*(state: BeaconState, epoch: Epoch): uint64 =
  # Return the number of committees at ``epoch``.
  let active_validator_indices = get_active_validator_indices(state, epoch)
  let committees_per_slot = clamp(
    len(active_validator_indices) div SLOTS_PER_EPOCH div TARGET_COMMITTEE_SIZE,
    1, SHARD_COUNT div SLOTS_PER_EPOCH).uint64
  result = committees_per_slot * SLOTS_PER_EPOCH

  # Otherwise, get_crosslink_committee(...) cannot access some committees.
  doAssert SHARD_COUNT >= result

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.0/specs/core/0_beacon-chain.md#get_current_epoch
func get_current_epoch*(state: BeaconState): Epoch =
  # Return the current epoch.
  doAssert state.slot >= GENESIS_SLOT, $state.slot
  compute_epoch_at_slot(state.slot)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_beacon-chain.md#get_randao_mix
func get_randao_mix*(state: BeaconState,
                     epoch: Epoch): Eth2Digest =
    ## Returns the randao mix at a recent ``epoch``.
    state.randao_mixes[epoch mod EPOCHS_PER_HISTORICAL_VECTOR]

func bytes_to_int*(data: openarray[byte]): uint64 =
  doAssert data.len == 8

  # Little-endian data representation
  result = 0
  for i in countdown(7, 0):
    result = result * 256 + data[i]

# Have 1, 4, 8, and 32-byte versions. 1+ more and maybe worth metaprogramming.
func int_to_bytes32*(x: uint64): array[32, byte] =
  ## Little-endian data representation
  ## TODO remove uint64 when those callers fade away
  littleEndian64(result[0].addr, x.unsafeAddr)

func int_to_bytes32*(x: Epoch): array[32, byte] {.borrow.}

func int_to_bytes8*(x: uint64): array[8, byte] =
  littleEndian64(result[0].addr, x.unsafeAddr)

func int_to_bytes1*(x: int): array[1, byte] =
  doAssert x >= 0
  doAssert x < 256

  result[0] = x.byte

func int_to_bytes4*(x: uint64): array[4, byte] =
  doAssert x >= 0'u64
  doAssert x < 2'u64^32

  # Little-endian data representation
  result[0] = ((x shr  0) and 0xff).byte
  result[1] = ((x shr  8) and 0xff).byte
  result[2] = ((x shr 16) and 0xff).byte
  result[3] = ((x shr 24) and 0xff).byte

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_beacon-chain.md#compute_domain
func compute_domain*(
    domain_type: DomainType,
    fork_version: array[4, byte] = [0'u8, 0, 0, 0]): Domain =
  result[0..3] = int_to_bytes4(domain_type.uint64)
  result[4..7] = fork_version

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.0/specs/core/0_beacon-chain.md#get_domain
func get_domain*(
    state: BeaconState, domain_type: DomainType, message_epoch: Epoch): Domain =
  ## Return the signature domain (fork version concatenated with domain type)
  ## of a message.
  let
    epoch = message_epoch
    fork_version = if epoch < state.fork.epoch:
        state.fork.previous_version
      else:
        state.fork.current_version
  compute_domain(domain_type, fork_version)

func get_domain*(state: BeaconState, domain_type: DomainType): Domain =
  get_domain(state, domain_type, get_current_epoch(state))

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.4/specs/core/0_beacon-chain.md#get_seed
func get_seed*(state: BeaconState, epoch: Epoch): Eth2Digest =
  # Generate a seed for the given ``epoch``.

  var seed_input : array[32*3, byte]

  # Detect potential underflow
  doAssert EPOCHS_PER_HISTORICAL_VECTOR >= MIN_SEED_LOOKAHEAD

  seed_input[0..31] =
    get_randao_mix(state,
      epoch + EPOCHS_PER_HISTORICAL_VECTOR - MIN_SEED_LOOKAHEAD - 1).data
  seed_input[32..63] =
    state.active_index_roots[epoch mod EPOCHS_PER_HISTORICAL_VECTOR].data
  seed_input[64..95] = int_to_bytes32(epoch)
  eth2hash(seed_input)
