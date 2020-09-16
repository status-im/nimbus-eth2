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
  ./spec/[datatypes, crypto, state_transition_block],
  ./block_pools/[chain_dag, clearance, quarantine, spec_cache],
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
      initDeque[VoluntaryExit](initialSize = MAX_VOLUNTARY_EXITS.int),
    chainDag: chainDag,
    quarantine: quarantine
   )

func addExitMessage(subpool: var auto, exitMessage, bound: auto) =
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
                                seq[VoluntaryExit] =
  ## Retrieve voluntary exits that may be added to a new block
  getExitMessagesForBlock[VoluntaryExit](
    pool.voluntary_exits, MAX_VOLUNTARY_EXITS)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#attester_slashing
proc validateAttesterSlashing*(
    pool: var ExitPool, attesterSlashing: AttesterSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] At least one index in the intersection of the attesting indices of
  # each attestation has not yet been seen in any prior attester_slashing (i.e.
  # attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices),
  # verify if any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))).
  #
  # This is what the spec states, but even when a validators was slashed using
  # proposer slashing it's still pointless relaying an attester slashing for a
  # validator; process_attester_slashing() will note not that validator as not
  # slashable. Therefore, check whether it's slashed for any reason.
  # TODO check for upstream spec disposition on this
  let
    attestation_1 = attester_slashing.attestation_1
    attestation_2 = attester_slashing.attestation_2
    # TODO sequtils2 should be able to make this more reasonable, from asSeq on
    # down
    attesting_indices_1 =
      toHashSet(mapIt(attestation_1.attesting_indices.asSeq, it.ValidatorIndex))
    attesting_indices_2 =
      toHashSet(mapIt(attestation_1.attesting_indices.asSeq, it.ValidatorIndex))
    attester_slashed_indices = attesting_indices_1 * attesting_indices_2
    # TODO

  # [REJECT] All of the conditions within process_attester_slashing pass
  # validation.
  # This is similar to process_attester_slashing, but both cut-down (it doesn't
  # have the loop over attesting indices) and using EpochRef caches, so there's
  # no real overlap in code terms with process_proposer_slashing().
  block:
    let tgtBlck_1 = pool.chainDag.getRef(attestation_1.data.target.root)
    if tgtBlck_1.isNil:
      pool.quarantine.addMissing(attestation_1.data.target.root)
      const err_str: cstring = "Attestation 1 target block unknown"
      return err((EVRESULT_IGNORE, err_str))

    let tgtBlck_2 = pool.chainDag.getRef(attestation_2.data.target.root)
    if tgtBlck_2.isNil:
      pool.quarantine.addMissing(attestation_2.data.target.root)
      const err_str: cstring = "Attestation 2 target block unknown"
      return err((EVRESULT_IGNORE, err_str))

    let
      epochRef_1 = pool.chainDag.getEpochRef(
        tgtBlck_1, attestation_1.data.target.epoch)
      epochRef_2 = pool.chainDag.getEpochRef(
        tgtBlck_2, attestation_2.data.target.epoch)
      fork = pool.chainDag.headState.data.data.fork
      genesis_validators_root =
        pool.chainDag.headState.data.data.genesis_validators_root

    if not is_slashable_attestation_data(
        attestation_1.data, attestation_2.data):
      const err_str: cstring = "Attestation data not slashable"
      return err((EVRESULT_REJECT, err_str))
    block:
      let v = is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef_1, attestation_1, {})
      if v.isErr():
        return err((EVRESULT_REJECT, v.error))
    block:
      let v = is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef_2, attestation_2, {})
      if v.isErr():
        return err((EVRESULT_REJECT, v.error))

  pool.attester_slashings.addExitMessage(
    attesterSlashing, MAX_ATTESTER_SLASHINGS)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#proposer_slashing
proc validateProposerSlashing*(
    pool: var ExitPool, proposerSlashing: ProposerSlashing):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] The proposer slashing is the first valid proposer slashing
  # received for the proposer with index
  # proposer_slashing.signed_header_1.message.proposer_index.
  #
  # This is what the spec states, but even when the validator was slashed from
  # attester slashing, it's still pointless to relay a proposer slashing for a
  # validator; process_proposer_slashing() will mark not that validator as not
  # slashable. Therefore, check whether it's slashed for any reason.
  # TODO check for upstream spec disposition on this

  # [REJECT] All of the conditions within process_proposer_slashing pass validation.

  # TODO not called yet, so vacuousness is fine

  pool.proposer_slashings.addExitMessage(
    proposerSlashing, MAX_PROPOSER_SLASHINGS)

  ok(true)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#voluntary_exit
proc validateVoluntaryExit*(
    pool: var ExitPool, voluntaryExit: VoluntaryExit):
    Result[bool, (ValidationResult, cstring)] =
  # [IGNORE] The voluntary exit is the first valid voluntary exit received for
  # the validator with index signed_voluntary_exit.message.validator_index.

  # [REJECT] All of the conditions within process_voluntary_exit pass
  # validation.

  # TODO not called yet, so vacuousness is fine

  pool.voluntary_exits.addExitMessage(
    voluntaryExit, MAX_VOLUNTARY_EXITS)

  ok(true)
