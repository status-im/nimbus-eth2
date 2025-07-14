# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec
import
  std/[algorithm],
  results,
  eth/p2p/discoveryv5/[node],
  kzg4844/[kzg],
  ssz_serialization/[
    proofs,
    types],
  ./crypto,
  ./[helpers, digest, beacon_time,
     validator],
  ./datatypes/[fulu, focil]

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#new-is_valid_inclusion_list_signature
func is_valid_inclusion_list_signature*(
    state: ForkyBeaconState,
    signed_inclusion_list: SignedInclusionList): bool =
  ## Check if the `signed_inclusion_list` has a valid signature
  let
    message = signed_inclusion_list.message
    pubkey =
      state.validators[message.validator_index].pubkeyData
    domain = get_domain(state, DOMAIN_INCLUSION_LIST_COMMITTEE,
      message.slot.epoch())
    signing_root =
      compute_signing_root(message, domain)
  blsVerify(pubkey, signing_root.data, signed_inclusion_list.signature)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#new-get_inclusion_list_committee
func resolve_inclusion_list_committee*(
    state: ForkyBeaconState,
    slot: Slot): HashSet[uint64] =
  ## Return the inclusion list committee for the given slot
  let
    seed = get_seed(state, slot.epoch(), DOMAIN_INCLUSION_LIST_COMMITTEE)
    indices =
      get_active_validator_indices(state, slot.epoch())

    start = (slot mod SLOTS_PER_EPOCH) * INCLUSION_LIST_COMMITTEE_SIZE
    end_i = start + INCLUSION_LIST_COMMITTEE_SIZE
    seq_len {.inject.} = indices.lenu64

  var res: HashSet[uint64]
  for i in 0..<INCLUSION_LIST_COMMITTEE_SIZE:
    let
      shuffledIdx = compute_shuffled_index(
        (start + i) mod seq_len,
        seq_len,
        seed)

    res.incl uint64(indices[shuffledIdx])

  res

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/validator.md#new-inclusion-list-committee-assignment
func get_inclusion_committee_assignment*(
    state: ForkyBeaconState,
    epoch: Epoch,
    validator_index: ValidatorIndex): Opt[Slot] =
  ## Returns the slot during the requested epoch in which the validator
  ## with the index `validator_index` is a member of the ILC.
  ## Returns None if no assignment is found.
  let
    next_epoch = Epoch(state.slot.epoch() + 1)
  doAssert epoch <= nextEpoch

  for slot in epoch.slots():
    let
      committee = resolve_inclusion_list_committee(state, slot)
    if validator_index in committee:
      return Opt.som(slot)

  Opt.none(Slot)
