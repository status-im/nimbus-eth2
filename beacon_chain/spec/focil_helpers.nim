# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Uncategorized helper functions from the spec
import
  std/[algorithm, sequtils],
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

const
  viewFreezeOffset = slotOffset(VIEW_FREEZE_CUTOFF)
  submissionDueOffset = slotOffset(INCLUSION_LIST_SUBMISSION_DUE)
  proposerCutoffOffset = slotOffset(PROPOSER_INCLUSION_LIST_CUT_OFF)

func inclusion_list_view_freeze*(slot: Slot): BeaconTime =
  slot.start_beacon_time() + viewFreezeOffset

func inclusion_list_submission_due*(slot: Slot): BeaconTime =
  slot.start_beacon_time() + submissionDueOffset

func inclusion_list_proposer_cutoff*(slot: Slot): BeaconTime =
  slot.start_beacon_time() + proposerCutoffOffset

func get_view_freeze_cutoff_ms*(): uint64 =
  uint64(viewFreezeOffset.nanoseconds div 1_000_000)

func get_inclusion_list_submission_due_ms*(): uint64 =
  uint64(submissionDueOffset.nanoseconds div 1_000_000)

func get_proposer_inclusion_list_cutoff_ms*(): uint64 =
  uint64(proposerCutoffOffset.nanoseconds div 1_000_000)

proc compute_inclusion_list_committee_root*(
    committee: HashSet[uint64]): Eth2Digest =
  ## Compute the SSZ root of the inclusion list committee
  var committeeList: sszTypes.List[uint64,
      sszTypes.Limit INCLUSION_LIST_COMMITTEE_SIZE]
  for validator in committee:
    discard committeeList.add(validator)
  hash_tree_root(committeeList)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#new-is_valid_inclusion_list_signature
func verify_inclusion_list_signature*(
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
  blsVerify(pubkey, signing_root.data, signature)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/_features/eip7805/beacon-chain.md#new-get_inclusion_list_committee
func resolve_inclusion_list_committee*(
    state: ForkyBeaconState,
    slot: Slot): HashSet[ValidatorIndex] =
  ## Return the inclusion list committee for the given slot
  let
    seed = get_seed(state, slot.epoch(), DOMAIN_INCLUSION_LIST_COMMITTEE)
    indices =
      get_active_validator_indices(state, epoch)

    start = (slot mod SLOTS_PER_EPOCH) * INCLUSION_LIST_COMMITTEE_SIZE
    end_i = start + INCLUSION_LIST_COMMITTEE_SIZE
    seq_len {.inject.} = indices.lenu64

  var res: HashSet[ValidatorIndex]
  for i in 0..<INCLUSION_LIST_COMMITTEE_SIZE:
    let
      shuffledIdx = compute_shuffled_index(
        ((start + i) mod seq_len).asUInt64,
        seq_len,
        seed)

    res.incl indices[shuffledIdx]

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
    start_slot = epoch.start_slot()

  doAssert epoch <= nextEpoch

  for epochSlot in epoch.slots():
    let
      slot = Slot(epochSlot + start_slot)
      committee = resolve_inclusion_list_committee(state, slot)
    if validator_index in committee:
      return Opt.som(slot)

  Opt.none(Slot)

proc process_inclusion_list*(
    store: var InclusionListStore,
    state: ForkyBeaconState,
    signed_inclusion_list: SignedInclusionList,
    wallTime: BeaconTime
) =
  ## Validate timing constraints and merge the inclusion list into the store.
  ## Mirrors the spec deadlines: tolerate the configured clock skew and only
  ## admit lists received before the view-freeze boundary. Late arrivals still
  ## go through the equivocation path but do not expand the required set.
  let message = signed_inclusion_list.message

  let
    slotStart = message.slot.start_beacon_time()
    earliestAllowed = slotStart - MAXIMUM_GOSSIP_CLOCK_DISPARITY
    latestTolerated =
      inclusion_list_proposer_cutoff(message.slot) + MAXIMUM_GOSSIP_CLOCK_DISPARITY

  if wallTime < earliestAllowed:
    # Too far in the future relative to our clock; rely on re-gossip and skip.
    return

  if wallTime > latestTolerated:
    # Way past the proposer cutoff; nothing to be gained from processing.
    return

  if not verify_inclusion_list_signature(state, signed_inclusion_list):
    return

  let
    committee = get_inclusion_list_committee(state, message.slot)
    committeeRoot = compute_inclusion_list_committee_root(committee)

  if message.inclusion_list_committee_root != committeeRoot:
    return

  let acceptBeforeFreeze =
    wallTime <= inclusion_list_view_freeze(message.slot)

  store.process_inclusion_list(message, accept = acceptBeforeFreeze)

proc get_inclusion_list_transactions*(
    store: InclusionListStore, state: ForkyBeaconState, slot: Slot
): seq[bellatrix.Transaction] =
  ## Collect the unique transactions from valid inclusion lists for ``slot``
  let
    committee = get_inclusion_list_committee(state, slot)
    committeeRoot = compute_inclusion_list_committee_root(committee)
    key = makeKey(slot, committeeRoot)
    equivocators = store.getEquivocatorsForKey(key)

  var aggregated: seq[bellatrix.Transaction]
  for inclusionList in store.getInclusionListsForKey(key):
    if inclusionList.validator_index in equivocators:
      continue
    for tx in inclusionList.transactions.items:
      if tx notin aggregated:
        aggregated.add(tx)

  aggregated
