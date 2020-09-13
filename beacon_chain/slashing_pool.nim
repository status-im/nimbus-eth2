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
  ./spec/[datatypes, crypto, state_transition_block],
  ./block_pools/[chain_dag, clearance, quarantine, spec_cache],
  ./beacon_node_types

export beacon_node_types, sets

logScope: topics = "slashpool"

proc init*(
    T: type SlashingPool, chainDag: ChainDAGRef, quarantine: QuarantineRef): T =
  ## Initialize an SlashingPool from the chainDag `headState`
  T(
    attester_slashings: initDeque(initialSize = MAX_ATTESTER_SLASHINGS),
    chainDag: chainDag,
    quarantine: quarantine
   )

func addAttesterSlashing(pool: var SlashingPool,
                         attestationSlashing: AttesterSlashing) =
  # Prefer newer to older attestater slashings
  while pool.attester_slashings.lenu64 >= MAX_ATTESTER_SLASHINGS:
    discard pool.attester_slashings.popFirst()

  pool.attester_slashings.addLast(attestationSlashing)

proc getAttesterSlashingsForBlock*(pool: var SlashingPool,
                                   state: BeaconState):
                                   seq[AttesterSlashing] =
  ## Retrieve attester slashings that may be added to a new block at the slot
  ## of the given state
  logScope: pcs = "retrieve_attester_slashing"

  for i in 0 ..< MAX_ATTESTER_SLASHINGS:
    if pool.attester_slashings.len == 0:
      break
    result.add pool.attester_slashings.popFirst()

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#attester_slashing
proc validateAttesterSlashing*(
    pool: var SlashingPool, attesterSlashing: AttesterSlashing): Result[bool, cstring] =
  # [IGNORE] At least one index in the intersection of the attesting indices of
  # each attestation has not yet been seen in any prior attester_slashing (i.e.
  # attester_slashed_indices = set(attestation_1.attesting_indices).intersection(attestation_2.attesting_indices),
  # verify if any(attester_slashed_indices.difference(prior_seen_attester_slashed_indices))).
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
    # TODO this arguably ties in with slashing protection in general

  # [REJECT] All of the conditions within process_attester_slashing pass
  # validation.
  # This is similar to process_attester_slashing, but both cut-down (it doesn't
  # have the loop over attesting indices) and using EpochRef caches, so there's
  # no real overlap in code terms with process_proposer_slashing().
  block:
    let tgtBlck_1 = pool.chainDag.getRef(attestation_1.data.target.root)
    if tgtBlck_1.isNil:
      pool.quarantine.addMissing(attestation_1.data.target.root)
      return err("Attestation 1 target block unknown")

    let tgtBlck_2 = pool.chainDag.getRef(attestation_2.data.target.root)
    if tgtBlck_2.isNil:
      pool.quarantine.addMissing(attestation_2.data.target.root)
      return err("Attestation 2 target block unknown")

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
      return err("Attestation data not slashable")
    ? is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef_1, attestation_1, {})
    ? is_valid_indexed_attestation(
        fork, genesis_validators_root, epochRef_2, attestation_2, {})

  pool.addAttesterSlashing(attesterSlashing)

  ok(true)
