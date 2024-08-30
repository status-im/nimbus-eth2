# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/sequtils, std/sets, std/lists,
  "."/[forks, ptc_status, validator],
  ./datatypes/epbs,
  "."/[
  beaconstate, eth2_merkleization, helpers, signatures,
  state_transition_block, state_transition_epoch]

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#is_valid_indexed_payload_attestation
proc is_valid_indexed_payload_attestation*(
    state: epbs.BeaconState,
    indexed_payload_attestation: IndexedPayloadAttestation): bool =

  # Verify that data is valid
  if indexed_payload_attestation.data.payload_status >=
      uint8(PAYLOAD_INVALID_STATUS):
    return false
    ## Check if ``indexed_attestation`` is not empty, has sorted and unique
    ## indices and has a valid aggregate signature.

  template is_sorted_and_unique(s: untyped): bool =
    var res = true
    for i in 1 ..< s.len:
      if s[i - 1].uint64 >= s[i].uint64:
        res = false
        break
    res

  if len(indexed_payload_attestation.attesting_indices) == 0:
    return false

  # Check if ``indexed_payload_attestation`` is has sorted and unique
  if not is_sorted_and_unique(indexed_payload_attestation.attesting_indices):
    return false

  # Verify aggregate signature
  let pubkeys = mapIt(
    indexed_payload_attestation.attesting_indices, state.validators[it].pubkey)

  let domain = get_domain(
    state.fork, DOMAIN_PTC_ATTESTER, GENESIS_EPOCH,
    state.genesis_validators_root)

  let signing_root = compute_signing_root(
    indexed_payload_attestation.data, domain)

  blsFastAggregateVerify(pubkeys, signing_root.data,
      indexed_payload_attestation.signature)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#is_parent_block_full
func is_parent_block_full*(state: epbs.BeaconState): bool =
  return state.latest_execution_payload_header.block_hash ==
      state.latest_block_hash

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#get_ptc
proc get_ptc(state: epbs.BeaconState, slot: Slot, cache: var StateCache,
    committee_bits: auto, data: epbs.AttestationData): seq[ValidatorIndex] =
  let
    epoch = epoch(slot)
    committees_per_slot = bit_floor(min(get_committee_count_per_slot(
        state, epoch, cache), PTC_SIZE))
    members_per_committee = (PTC_SIZE div committees_per_slot)

  var
    validator_indices: seq[ValidatorIndex]

  validator_indices.setLen(PTC_SIZE)

  for committee_index in get_committee_indices(committee_bits):
    for _, beacon_committee in get_beacon_committee(
        state, data.slot, committee_index, cache):
      validator_indices.add(beacon_committee)

  return validator_indices

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#modified-get_attesting_indices
proc get_attesting_indices(state: epbs.BeaconState,
    attestation: epbs.Attestation, cache: var StateCache, 
    cfg: RuntimeConfig): HashSet[ValidatorIndex] =

  var
    output: HashSet[ValidatorIndex]
    committee_offset = 0
    committee_attesters: HashSet[ValidatorIndex]

  for committee_index in get_committee_indices(attestation.committee_bits):
    for i, validator_index in get_beacon_committee(state, attestation.data.slot,
        committee_index, cache):
      if attestation.aggregation_bits[committee_offset + i]:
        committee_attesters.incl(validator_index)

    # Merge the current committee_attesters set with 
    # the overall output set of attesting validators
    output = output.union(committee_attesters)

    committee_offset += len(get_beacon_committee(state, attestation.data.slot,
      committee_index, cache))

  if epoch(attestation.data.slot) < cfg.EIP7732_FORK_EPOCH:
    return output

  let ptc = get_ptc(state, attestation.data.slot, cache,
    attestation.committee_bits, attestation.data)
  return output - ptc.toHashSet()

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#get_payload_attesting_indices
proc get_payload_attesting_indices(state: epbs.BeaconState, slot: Slot,
    payload_attestation: PayloadAttestation, cache: var StateCache,
    attestation: epbs.Attestation): List[ValidatorIndex, Limit PTC_SIZE] =

  let ptc = get_ptc(state, slot, cache, attestation.committee_bits,
    attestation.data)
  var
    output: List[ValidatorIndex, Limit PTC_SIZE]
    pos = 0

  for i, index in ptc.pairs:
    if payload_attestation.aggregation_bits[i]:
      output[pos] = index
      pos += 1

  output

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/beacon-chain.md#get_indexed_payload_attestation
proc get_indexed_payload_attestation*(state: var epbs.BeaconState, slot: Slot,
    payload_attestation: PayloadAttestation, cache: var StateCache,
    attestation: epbs.Attestation): IndexedPayloadAttestation =

  let attesting_indices = get_payload_attesting_indices(
    state, slot, payload_attestation, cache, attestation)

  IndexedPayloadAttestation(
    attesting_indices: attesting_indices,
    data: payload_attestation.data,
    signature: payload_attestation.signature
  )