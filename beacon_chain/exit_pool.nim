# beacon_chain
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard libraries
  std/[options, sequtils, sets, tables],
  # Status libraries
  chronicles, json_serialization/std/sets as jsonSets,
  # Internal
  ./spec/[crypto, datatypes, helpers, state_transition_block],
  ./block_pools/[chain_dag, clearance, quarantine],
  ./beacon_node_types

export beacon_node_types, sets

logScope: topics = "exitpool"

proc init*(
    T: type ExitPool, chainDag: ChainDAGRef, quarantine: QuarantineRef): T =
  ## Initialize an ExitPool from the chainDag `headState`
  T(
    attester_slashings:
      initOrderedTable[(seq[uint64], seq[uint64]), AttesterSlashing](
        initialSize = tables.rightSize(MAX_ATTESTER_SLASHINGS.int + 1)),
    proposer_slashings:
      initOrderedTable[uint64, ProposerSlashing](
        initialSize = tables.rightSize(MAX_PROPOSER_SLASHINGS.int + 1)),
    voluntary_exits:
      initOrderedTable[uint64, SignedVoluntaryExit](
        initialSize = tables.rightSize(MAX_VOLUNTARY_EXITS.int + 1)),
    chainDag: chainDag,
    quarantine: quarantine
   )

func addExitMessage*[T, U](
    subpool: var OrderedTable[T, U], exitMessageKey: T, exitMessage: U,
    bound: uint64) =
  subpool[exitMessageKey] = exitMessage

  # Prefer newer to older exit messages
  if subpool.lenu64 > bound:
    let excess = subpool.lenu64 - bound
    var delKeys: seq[T]
    for k in subpool.keys():
      delKeys.add k
      if delKeys.lenu64 >= excess:
        break
    for k in delKeys:
      subpool.del k

  doAssert subpool.lenu64 <= bound

func getExitMessagesForBlock[T, U](
    subpool: var OrderedTable[T, U], bound: uint64): seq[U] =
  var resultKeys: seq[T]

  for (k, msg) in subpool.pairs():
    resultKeys.add k
    result.add msg
    if result.lenu64 >= bound:
      break

  for k in resultKeys:
    subpool.del k

  doAssert result.lenu64 <= bound

func getAttesterSlashingsForBlock*(pool: var ExitPool):
                                   seq[AttesterSlashing] =
  ## Retrieve attester slashings that may be added to a new block
  getExitMessagesForBlock[(seq[uint64], seq[uint64]), AttesterSlashing](
    pool.attester_slashings, MAX_ATTESTER_SLASHINGS)

func getProposerSlashingsForBlock*(pool: var ExitPool):
                                   seq[ProposerSlashing] =
  ## Retrieve proposer slashings that may be added to a new block
  getExitMessagesForBlock[uint64, ProposerSlashing](
    pool.proposer_slashings, MAX_PROPOSER_SLASHINGS)

func getVoluntaryExitsForBlock*(pool: var ExitPool):
                                seq[SignedVoluntaryExit] =
  ## Retrieve voluntary exits that may be added to a new block
  getExitMessagesForBlock[uint64, SignedVoluntaryExit](
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
  let
    attestation_1_indices =
      attester_slashing.attestation_1.attesting_indices.asSeq
    attestation_2_indices =
      attester_slashing.attestation_2.attesting_indices.asSeq
    attester_slashed_indices =
      toHashSet(mapIt(attestation_1_indices, it.ValidatorIndex)) *
      toHashSet(mapIt(attestation_2_indices, it.ValidatorIndex))

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
  addExitMessage[(seq[uint64], seq[uint64]), AttesterSlashing](
    pool.attester_slashings, (attestation_1_indices, attestation_2_indices),
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
  addExitMessage[uint64, ProposerSlashing](
    pool.proposer_slashings,
    proposer_slashing.signed_header_1.message.proposer_index,
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
  addExitMessage[uint64, SignedVoluntaryExit](
    pool.voluntary_exits, signed_voluntary_exit.message.validator_index,
    signed_voluntary_exit, MAX_VOLUNTARY_EXITS)

  ok(true)

func removeBeaconBlockIncludedMessages*(
    pool: var ExitPool, blockBody: BeaconBlockBody) =
  # Once validated the REJECT conditions can't ever become true by other
  # network actions. However, the IGNORE conditions can, so check. These
  # are only run after a block is (effectively) resolved, so we keep the
  # exit messages which might only have been picked up by nodes on other
  # DAG branches.
  for proposer_slashing in blockBody.proposer_slashings:
    pool.proposer_slashings.del(
      proposer_slashing.signed_header_1.message.proposer_index)

  for attester_slashing in blockBody.attester_slashings:
    pool.attester_slashings.del((
      attester_slashing.attestation_1.attesting_indices.asSeq,
      attester_slashing.attestation_2.attesting_indices.asSeq))

  for signed_voluntary_exit in blockBody.voluntary_exits:
    pool.voluntary_exits.del(signed_voluntary_exit.message.validator_index)
