# beacon_chain
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  std/[deques, options, sequtils, sets],
  # Status libraries
  chronicles, json_serialization/std/sets as jsonSets,
  # Internal
  ./spec/[crypto, datatypes, helpers, state_transition_block],
  ./block_pools/[chain_dag, clearance, quarantine],
  ./beacon_node_types

export beacon_node_types, sets

logScope: topics = "slashpool"

proc init*(
    T: type ExitPool, chainDag: ChainDAGRef, quarantine: QuarantineRef): T =
  ## Initialize an ExitPool from the chainDag `headState`
  T(
    attester_slashings:
      initDeque[AttesterSlashing](initialSize = MAX_ATTESTER_SLASHINGS.int),
    proposer_slashings:
      initDeque[ProposerSlashing](initialSize = MAX_PROPOSER_SLASHINGS.int),
    voluntary_exits:
      initDeque[SignedVoluntaryExit](initialSize = MAX_VOLUNTARY_EXITS.int),
    chainDag: chainDag,
    quarantine: quarantine
   )

func addExitMessage*(subpool: var auto, exitMessage, bound: auto) =
  # Prefer newer to older exit message
  while subpool.lenu64 >= bound:
    discard subpool.popFirst()

  subpool.addLast(exitMessage)
  doAssert subpool.lenu64 <= bound

func getExitMessagesForBlock[T](subpool: var Deque[T], bound: uint64): seq[T] =
  for i in 0 ..< bound:
    if subpool.len == 0:
      break
    result.add subpool.popFirst()

  doAssert result.lenu64 <= bound

func getAttesterSlashingsForBlock*(pool: var ExitPool):
                                   seq[AttesterSlashing] =
  ## Retrieve attester slashings that may be added to a new block
  getExitMessagesForBlock[AttesterSlashing](
    pool.attester_slashings, MAX_ATTESTER_SLASHINGS)

func getProposerSlashingsForBlock*(pool: var ExitPool):
                                   seq[ProposerSlashing] =
  ## Retrieve proposer slashings that may be added to a new block
  getExitMessagesForBlock[ProposerSlashing](
    pool.proposer_slashings, MAX_PROPOSER_SLASHINGS)

func getVoluntaryExitsForBlock*(pool: var ExitPool):
                                seq[SignedVoluntaryExit] =
  ## Retrieve voluntary exits that may be added to a new block
  getExitMessagesForBlock[SignedVoluntaryExit](
    pool.voluntary_exits, MAX_VOLUNTARY_EXITS)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.3/specs/phase0/p2p-interface.md#attester_slashing
proc validateAttesterSlashing*(
    pool: var ExitPool, attester_slashing: AttesterSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] At least one index in the intersection of the attesting indices of
  # each attestation has not yet been seen in any prior attester_slashing (i.e.
  # attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices),
  # verify if any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))).
  # TODO sequtils2 should be able to make this more reasonable, from asSeq on
  # down
  let attester_slashed_indices =
    toHashSet(mapIt(
      attester_slashing.attestation_1.attesting_indices.asSeq,
      it.ValidatorIndex)) *
    toHashSet(mapIt(
      attester_slashing.attestation_2.attesting_indices.asSeq,
      it.ValidatorIndex))

  if not disjoint(
      attester_slashed_indices, pool.prior_seen_attester_slashed_indices):
    const err_str: cstring =
      "validateAttesterSlashing: attester-slashed index already attester-slashed"
    return err((EVRESULT_IGNORE, err_str))

  # [REJECT] All of the conditions within process_attester_slashing pass
  # validation.
  var cache =
   getStateCache(pool.chainDag.head,
     pool.chainDag.headState.data.data.slot.compute_epoch_at_slot)
  let attester_slashing_validity =
    check_attester_slashing(
      pool.chainDag.headState.data.data, attester_slashing, {}, cache)
  if attester_slashing_validity.isErr:
    return err((EVRESULT_REJECT, attester_slashing_validity.error))

  pool.prior_seen_attester_slashed_indices.incl attester_slashed_indices
  pool.attester_slashings.addExitMessage(
    attester_slashing, MAX_ATTESTER_SLASHINGS)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.3/specs/phase0/p2p-interface.md#proposer_slashing
proc validateProposerSlashing*(
    pool: var ExitPool, proposer_slashing: ProposerSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] The proposer slashing is the first valid proposer slashing
  # received for the proposer with index
  # proposer_slashing.signed_header_1.message.proposer_index.
  if proposer_slashing.signed_header_1.message.proposer_index.ValidatorIndex in
      pool.prior_seen_proposer_slashed_indices:
    const err_str: cstring =
      "validateProposerSlashing: proposer-slashed index already proposer-slashed"
    return err((EVRESULT_IGNORE, err_str))

  # [REJECT] All of the conditions within process_proposer_slashing pass validation.
  var cache =
   getStateCache(pool.chainDag.head,
     pool.chainDag.headState.data.data.slot.compute_epoch_at_slot)
  let proposer_slashing_validity =
    check_proposer_slashing(
      pool.chainDag.headState.data.data, proposer_slashing, {}, cache)
  if proposer_slashing_validity.isErr:
    return err((EVRESULT_REJECT, proposer_slashing_validity.error))

  pool.prior_seen_proposer_slashed_indices.incl(
    proposer_slashing.signed_header_1.message.proposer_index.ValidatorIndex)
  pool.proposer_slashings.addExitMessage(
    proposer_slashing, MAX_PROPOSER_SLASHINGS)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.3/specs/phase0/p2p-interface.md#voluntary_exit
proc validateVoluntaryExit*(
    pool: var ExitPool, signed_voluntary_exit: SignedVoluntaryExit):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] The voluntary exit is the first valid voluntary exit received for
  # the validator with index signed_voluntary_exit.message.validator_index.
  if signed_voluntary_exit.message.validator_index >=
      pool.chainDag.headState.data.data.validators.lenu64:
    const err_str: cstring = "validateVoluntaryExit: validator index too high"
    return err((EVRESULT_IGNORE, err_str))
  if signed_voluntary_exit.message.validator_index.ValidatorIndex in
      pool.prior_seen_voluntary_exit_indices:
    const err_str: cstring = "validateVoluntaryExit: validator index already voluntarily exited"
    return err((EVRESULT_IGNORE, err_str))

  # [REJECT] All of the conditions within process_voluntary_exit pass
  # validation.
  var cache =
   getStateCache(pool.chainDag.head,
     pool.chainDag.headState.data.data.slot.compute_epoch_at_slot)
  let voluntary_exit_validity =
    check_voluntary_exit(
      pool.chainDag.headState.data.data, signed_voluntary_exit, {}, cache)
  if voluntary_exit_validity.isErr:
    return err((EVRESULT_REJECT, voluntary_exit_validity.error))

  pool.prior_seen_voluntary_exit_indices.incl(
    signed_voluntary_exit.message.validator_index.ValidatorIndex)
  pool.voluntary_exits.addExitMessage(
    signed_voluntary_exit, MAX_VOLUNTARY_EXITS)

  ok(true)
