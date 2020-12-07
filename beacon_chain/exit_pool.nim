# beacon_chain
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  std/[deques, options, sequtils, sets, tables],
  # Status libraries
  chronicles, json_serialization/std/sets as jsonSets,
  # Internal
  ./spec/[crypto, datatypes, helpers, state_transition_block],
  ./block_pools/[chain_dag, clearance, quarantine],
  ./beacon_node_types

export beacon_node_types, sets

logScope: topics = "exitpool"

const
  ATTESTER_SLASHINGS_BOUND = MAX_ATTESTER_SLASHINGS * 2
  PROPOSER_SLASHINGS_BOUND = MAX_PROPOSER_SLASHINGS * 2
  VOLUNTARY_EXITS_BOUND = MAX_VOLUNTARY_EXITS * 2

proc init*(
    T: type ExitPool, chainDag: ChainDAGRef, quarantine: QuarantineRef): T =
  ## Initialize an ExitPool from the chainDag `headState`
  T(
    # Allow for filtering out some exit messages during block production
    attester_slashings:
      initDeque[AttesterSlashing](initialSize = ATTESTER_SLASHINGS_BOUND.int),
    proposer_slashings:
      initDeque[ProposerSlashing](initialSize = PROPOSER_SLASHINGS_BOUND.int),
    voluntary_exits:
      initDeque[SignedVoluntaryExit](initialSize = VOLUNTARY_EXITS_BOUND.int),
    chainDag: chainDag,
    quarantine: quarantine
   )

func addExitMessage*(subpool: var auto, exitMessage, bound: auto) =
  # Prefer newer to older exit messages
  while subpool.lenu64 >= bound:
    discard subpool.popFirst()

  subpool.addLast(exitMessage)
  doAssert subpool.lenu64 <= bound

iterator getValidatorIndices(attester_slashing: AttesterSlashing): uint64 =
  # TODO rely on sortedness and do this sans memory allocations, but it's only
  # when producing a beacon block, which is rare bottlenecked elsewhere.
  let
    attestation_1_indices =
      attester_slashing.attestation_1.attesting_indices.asSeq
    attestation_2_indices =
      attester_slashing.attestation_2.attesting_indices.asSeq
    attester_slashed_indices =
      toHashSet(attestation_1_indices) * toHashSet(attestation_2_indices)

  for validator_index in attester_slashed_indices:
    yield validator_index

iterator getValidatorIndices(proposer_slashing: ProposerSlashing): uint64 =
  yield proposer_slashing.signed_header_1.message.proposer_index

iterator getValidatorIndices(voluntary_exit: SignedVoluntaryExit): uint64 =
  yield voluntary_exit.message.validator_index

# TODO stew/sequtils2
template allIt(s, pred: untyped): bool =
  # https://github.com/nim-lang/Nim/blob/version-1-2/lib/pure/collections/sequtils.nim#L640-L662
  # without the items(...)
  var result = true
  for it {.inject.} in s:
    if not pred:
      result = false
      break
  result

func getExitMessagesForBlock[T](
    subpool: var Deque[T], pool: var ExitPool, bound: uint64): seq[T] =
  # Approach taken here is to simply collect messages, effectively, a circular
  # buffer and only re-validate that they haven't already found themselves out
  # of the network eventually via some exit message at block construction time
  # at which point we use exit_epoch. It doesn't matter which of these message
  # types has triggered that exit, as the validation on incoming messages will
  # find it to either be IGNORE (if it's the same type of exit message) or, if
  # it's a different type, REJECT. Neither is worth packaging into BeaconBlock
  # messages we broadcast.
  #
  # Beyond that, no other criterion of the exit messages' validity changes from
  # when they were created, so given that we validated them to start with, they
  # otherwise remain as valid as when we received them. There's no need to thus
  # re-validate them on their way out.
  #
  # This overall approach handles a scenario wherein we receive an exit message
  # over gossip and put it in the pool; receive a block X, with that message in
  # it, and select it as head; then orphan block X and build instead on X-1. If
  # this occurs, only validating after the fact ensures that we still broadcast
  # out those exit messages that were in orphaned block X by not having eagerly
  # removed them, if we have the chance.
  while true:
    if subpool.len == 0 or result.lenu64 >= bound:
      break

    # Prefer recent messages
    let exit_message = subpool.popLast()

    if allIt(
        getValidatorIndices(exit_message),
        pool.chainDag.headState.data.data.validators[it].exit_epoch !=
          FAR_FUTURE_EPOCH):
      # A beacon block exit message already targeted all these validators
      continue

    result.add exit_message

  subpool.clear()
  doAssert result.lenu64 <= bound

func getAttesterSlashingsForBlock*(pool: var ExitPool):
                                   seq[AttesterSlashing] =
  ## Retrieve attester slashings that may be added to a new block
  getExitMessagesForBlock[AttesterSlashing](
    pool.attester_slashings, pool, MAX_ATTESTER_SLASHINGS)

func getProposerSlashingsForBlock*(pool: var ExitPool):
                                   seq[ProposerSlashing] =
  ## Retrieve proposer slashings that may be added to a new block
  getExitMessagesForBlock[ProposerSlashing](
    pool.proposer_slashings, pool, MAX_PROPOSER_SLASHINGS)

func getVoluntaryExitsForBlock*(pool: var ExitPool):
                                seq[SignedVoluntaryExit] =
  ## Retrieve voluntary exits that may be added to a new block
  getExitMessagesForBlock[SignedVoluntaryExit](
    pool.voluntary_exits, pool, MAX_VOLUNTARY_EXITS)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/p2p-interface.md#attester_slashing
proc validateAttesterSlashing*(
    pool: var ExitPool, attester_slashing: AttesterSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] At least one index in the intersection of the attesting indices of
  # each attestation has not yet been seen in any prior attester_slashing (i.e.
  # attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices),
  # verify if any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))).
  # TODO sequtils2 should be able to make this more reasonable, from asSeq on
  # down, and can sort and just find intersection that way
  let
    attestation_1_indices =
      attester_slashing.attestation_1.attesting_indices.asSeq
    attestation_2_indices =
      attester_slashing.attestation_2.attesting_indices.asSeq
    attester_slashed_indices =
      toHashSet(attestation_1_indices) * toHashSet(attestation_2_indices)

  if not disjoint(
      attester_slashed_indices, pool.prior_seen_attester_slashed_indices):
    return err((ValidationResult.Ignore, cstring(
      "validateAttesterSlashing: attester-slashed index already attester-slashed")))

  # [REJECT] All of the conditions within process_attester_slashing pass
  # validation.
  var cache =
   getStateCache(pool.chainDag.head,
     pool.chainDag.headState.data.data.slot.compute_epoch_at_slot)
  let attester_slashing_validity =
    check_attester_slashing(
      pool.chainDag.headState.data.data, attester_slashing, {}, cache)
  if attester_slashing_validity.isErr:
    return err((ValidationResult.Reject, attester_slashing_validity.error))

  pool.prior_seen_attester_slashed_indices.incl attester_slashed_indices
  pool.attester_slashings.addExitMessage(
    attester_slashing, ATTESTER_SLASHINGS_BOUND)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/p2p-interface.md#proposer_slashing
proc validateProposerSlashing*(
    pool: var ExitPool, proposer_slashing: ProposerSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] The proposer slashing is the first valid proposer slashing
  # received for the proposer with index
  # proposer_slashing.signed_header_1.message.proposer_index.
  if proposer_slashing.signed_header_1.message.proposer_index in
      pool.prior_seen_proposer_slashed_indices:
    return err((ValidationResult.Ignore, cstring(
      "validateProposerSlashing: proposer-slashed index already proposer-slashed")))

  # [REJECT] All of the conditions within process_proposer_slashing pass validation.
  var cache =
   getStateCache(pool.chainDag.head,
     pool.chainDag.headState.data.data.slot.compute_epoch_at_slot)
  let proposer_slashing_validity =
    check_proposer_slashing(
      pool.chainDag.headState.data.data, proposer_slashing, {}, cache)
  if proposer_slashing_validity.isErr:
    return err((ValidationResult.Reject, proposer_slashing_validity.error))

  pool.prior_seen_proposer_slashed_indices.incl(
    proposer_slashing.signed_header_1.message.proposer_index)
  pool.proposer_slashings.addExitMessage(
    proposer_slashing, PROPOSER_SLASHINGS_BOUND)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.0/specs/phase0/p2p-interface.md#voluntary_exit
proc validateVoluntaryExit*(
    pool: var ExitPool, signed_voluntary_exit: SignedVoluntaryExit):
    Result[void, (ValidationResult, cstring)] =
  # [IGNORE] The voluntary exit is the first valid voluntary exit received for
  # the validator with index signed_voluntary_exit.message.validator_index.
  if signed_voluntary_exit.message.validator_index >=
      pool.chainDag.headState.data.data.validators.lenu64:
    return err((ValidationResult.Ignore, cstring(
      "validateVoluntaryExit: validator index too high")))
  if signed_voluntary_exit.message.validator_index in
      pool.prior_seen_voluntary_exit_indices:
    return err((ValidationResult.Ignore, cstring(
      "validateVoluntaryExit: validator index already voluntarily exited")))

  # [REJECT] All of the conditions within process_voluntary_exit pass
  # validation.
  var cache =
   getStateCache(pool.chainDag.head,
     pool.chainDag.headState.data.data.slot.compute_epoch_at_slot)
  let voluntary_exit_validity =
    check_voluntary_exit(
      pool.chainDag.headState.data.data, signed_voluntary_exit, {}, cache)
  if voluntary_exit_validity.isErr:
    return err((ValidationResult.Reject, voluntary_exit_validity.error))

  pool.prior_seen_voluntary_exit_indices.incl(
    signed_voluntary_exit.message.validator_index)
  pool.voluntary_exits.addExitMessage(
    signed_voluntary_exit, VOLUNTARY_EXITS_BOUND)

  ok()
