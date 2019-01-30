# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Uncategorized helper functions from the spec

import ./datatypes, ./digest, sequtils, math

# TODO spec candidate? there's bits in nim-ranges but that one has some API
#      issues regarding bit endianess that need resolving..
func bitIsSet*(bitfield: openArray[byte], index: int): bool =
  (bitfield[index div 8] shr byte(7 - (index mod 8))) mod 2 > 0'u8

func bitSet*(bitfield: var openArray[byte], index: int) =
  bitfield[index div 8] = bitfield[index div 8] or 1'u8 shl (7 - (index mod 8))

func mod_get[T](arr: openarray[T], pos: Natural): T =
  arr[pos mod arr.len]

func shuffle*[T](values: seq[T], seed: Eth2Digest): seq[T] =
  ## Returns the shuffled ``values`` with seed as entropy.
  ## TODO: this calls out for tests, but I odn't particularly trust spec
  ## right now.

  let values_count = values.len

  const
    # Entropy is consumed from the seed in 3-byte (24 bit) chunks.
    rand_bytes = 3
    # The highest possible result of the RNG.
    rand_max = 2^(rand_bytes * 8) - 1

  # The range of the RNG places an upper-bound on the size of the list that
  # may be shuffled. It is a logic error to supply an oversized list.
  assert values_count < rand_max

  result = values
  var
    source = seed
    index = 0
  while index < values_count - 1:
    # Re-hash the `source` to obtain a new pattern of bytes.
    source = eth2hash source.data

    # Iterate through the `source` bytes in 3-byte chunks.
    for pos in countup(0, 29, 3):
      let remaining = values_count - index
      if remaining == 1:
        break

      # Read 3-bytes of `source` as a 24-bit big-endian integer.
      let sample_from_source =
        source.data[pos].ValidatorIndex shl 16 or
        source.data[pos+1].ValidatorIndex shl 8 or
        source.data[pos+2].ValidatorIndex

      # Sample values greater than or equal to `sample_max` will cause
      # modulo bias when mapped into the `remaining` range.
      let sample_max = rand_max - rand_max mod remaining

      # Perform a swap if the consumed entropy will not cause modulo bias.
      if sample_from_source < sample_max:
        # Select a replacement index for the current index.
        let replacement_position = sample_from_source mod remaining + index
        swap result[index], result[replacement_position]
        inc index

func split*[T](lst: openArray[T], N: Positive): seq[seq[T]] =
  ## split lst in N pieces, with each piece having `len(lst) div N` or
  ## `len(lst) div N + 1` pieces
  # TODO: implement as an iterator
  result = newSeq[seq[T]](N)
  for i in 0 ..< N:
    result[i] = lst[lst.len * i div N ..< lst.len * (i+1) div N] # TODO: avoid alloc via toOpenArray

func get_new_recent_block_roots*(old_block_roots: seq[Eth2Digest],
                                  parent_slot, current_slot: int64,
                                  parent_hash: Eth2Digest
                                  ): seq[Eth2Digest] =

  # Should throw for `current_slot - CYCLE_LENGTH * 2 - 1` according to spec comment
  let d = current_slot - parent_slot
  result = old_block_roots[d .. ^1]
  for _ in 0 ..< min(d, old_block_roots.len):
    result.add parent_hash

func ceil_div8*(v: int): int = (v + 7) div 8 # TODO use a proper bitarray!

func repeat_hash*(v: Eth2Digest, n: SomeInteger): Eth2Digest =
  # Spec version:
  # if n == 0: v
  # else: repeat_hash(eth2hash(v.data), n - 1)
  # Nim is pretty bad at recursion though (max 2k levels / no tco), so:
  result = v
  var n = n
  while n != 0:
    result = eth2hash(result.data)
    dec n

func get_shard_committees_index*(state: BeaconState, slot: uint64): uint64 =
  # TODO temporary adapter; remove when all users gone
  ## Warning: as it stands, this helper only works during state updates _after_
  ## state.slot has been incremented but before shard_committees_at_slots has
  ## been updated!
  # TODO spec unsigned-unsafe here
  doAssert slot + (state.slot mod EPOCH_LENGTH) + EPOCH_LENGTH > state.slot
  slot + (state.slot mod EPOCH_LENGTH) + EPOCH_LENGTH - state.slot

func integer_squareroot*(n: SomeInteger): SomeInteger =
  ## The largest integer ``x`` such that ``x**2`` is less than ``n``.
  var
    x = n
    y = (x + 1) div 2
  while y < x:
    x = y
    y = (x + n div x) div 2
  x

func get_fork_version*(fork: Fork, epoch: EpochNumber): uint64 =
  if epoch < fork.epoch:
    fork.previous_version
  else:
    fork.current_version

func get_domain*(
    fork: Fork, slot: uint64, domain_type: SignatureDomain): uint64 =
  # TODO Slot overflow? Or is slot 32 bits for all intents and purposes?
  (get_fork_version(fork, slot) shl 32) + domain_type.uint32

func is_power_of_2*(v: uint64): bool = (v and (v-1)) == 0

func merkle_root*(values: openArray[Eth2Digest]): Eth2Digest =
  # o = [0] * len(values) + values
  # for i in range(len(values)-1, 0, -1):
  #     o[i] = hash(o[i*2] + o[i*2+1])
  # return o[1]
  # TODO
  discard

proc is_double_vote*(attestation_data_1: AttestationData,
                     attestation_data_2: AttestationData): bool =
  ## Assumes ``attestation_data_1`` is distinct from ``attestation_data_2``.
  ## Returns True if the provided ``AttestationData`` are slashable
  ## due to a 'double vote'.
  ## A double vote is when a validator votes for two attestations within the
  ## same slot - doing so means risking getting slashed.
  attestation_data_1.slot == attestation_data_2.slot

func slot_to_epoch*(slot: SlotNumber): EpochNumber =
  slot div EPOCH_LENGTH

proc is_surround_vote*(attestation_data_1: AttestationData,
                       attestation_data_2: AttestationData): bool =
  ## Assumes ``attestation_data_1`` is distinct from ``attestation_data_2``.
  ## Returns True if the provided ``AttestationData`` are slashable
  ## due to a 'surround vote'.
  ## Note: parameter order matters as this function only checks
  ## that ``attestation_data_1`` surrounds ``attestation_data_2``.
  let
    source_epoch_1 = attestation_data_1.justified_epoch
    source_epoch_2 = attestation_data_2.justified_epoch
    target_epoch_1 = slot_to_epoch(attestation_data_1.slot)
    target_epoch_2 = slot_to_epoch(attestation_data_2.slot)

  (
    (source_epoch_1 < source_epoch_2) and
    (source_epoch_2 + 1 == target_epoch_2) and
    (target_epoch_2 < target_epoch_1)
  )

func is_active_validator*(validator: Validator, epoch: EpochNumber): bool =
  ### Checks if validator is active
  validator.activation_epoch <= epoch and epoch < validator.exit_epoch

func get_active_validator_indices*(validators: openArray[Validator], epoch: EpochNumber): seq[ValidatorIndex] =
  ## Gets indices of active validators from validators
  for idx, val in validators:
    if is_active_validator(val, epoch):
      result.add idx.ValidatorIndex

func get_epoch_committee_count*(active_validator_count: int): uint64 =
  clamp(
    active_validator_count div EPOCH_LENGTH div TARGET_COMMITTEE_SIZE,
    1, SHARD_COUNT div EPOCH_LENGTH).uint64 * EPOCH_LENGTH

func get_current_epoch_committee_count*(state: BeaconState): uint64 =
  let current_active_validators = get_active_validator_indices(
    state.validator_registry,
    state.current_calculation_epoch,
  )
  return get_epoch_committee_count(len(current_active_validators))

func get_current_epoch*(state: BeaconState): EpochNumber =
  slot_to_epoch(state.slot)

## TODO I've been moving things into helpers because of layering issues
## but create DAG of which helper functions ref others and topo sort to
## refactor all of this mess.
func get_randao_mix*(state: BeaconState,
                     epoch: EpochNumber): Eth2Digest =
    ## Returns the randao mix at a recent ``epoch``.
    assert get_current_epoch(state) - LATEST_RANDAO_MIXES_LENGTH < epoch
    assert epoch <= get_current_epoch(state)

    state.latest_randao_mixes[epoch mod LATEST_RANDAO_MIXES_LENGTH]

func get_active_index_root(state: BeaconState, epoch: EpochNumber): Eth2Digest =
  # Returns the index root at a recent ``epoch``.
  assert get_current_epoch(state) - LATEST_INDEX_ROOTS_LENGTH < epoch
  assert epoch <= get_current_epoch(state) + 1
  state.latest_index_roots[epoch mod LATEST_INDEX_ROOTS_LENGTH]

func generate_seed*(state: BeaconState, epoch: EpochNumber): Eth2Digest =
  # Generate a seed for the given ``epoch``.

  var seed_input : array[32*2, byte]
  seed_input[0..31] = get_randao_mix(state, epoch - SEED_LOOKAHEAD).data
  seed_input[32..63] = get_active_index_root(state, epoch).data
  eth2hash(seed_input)
