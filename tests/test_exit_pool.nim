# beacon_chain
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import chronicles, chronos
import eth/keys
import ../beacon_chain/spec/[datatypes/base, forks, presets]
import ../beacon_chain/consensus_object_pools/[
    block_quarantine, blockchain_dag, exit_pool]
import "."/[testutil, testdbutil]

suite "Exit pool testing suite":
  setup:
    let
      validatorMonitor = newClone(ValidatorMonitor.init())
      dag = init(
        ChainDAGRef, defaultRuntimeConfig, makeTestDB(SLOTS_PER_EPOCH * 3),
        validatorMonitor, {})
      pool = newClone(ExitPool.init(dag))

  test "addExitMessage/getProposerSlashingMessage":
    for i in 0'u64 .. MAX_PROPOSER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        let msg = ProposerSlashing(signed_header_1: SignedBeaconBlockHeader(
            message: BeaconBlockHeader(proposer_index: j)))

        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)
      withState(dag.headState.data):
        check:
          pool[].getBeaconBlockExits(state.data).proposer_slashings.lenu64 ==
            min(i + 1, MAX_PROPOSER_SLASHINGS)
          pool[].getBeaconBlockExits(state.data).proposer_slashings.len == 0

  test "addExitMessage/getAttesterSlashingMessage":
    for i in 0'u64 .. MAX_ATTESTER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        let msg = AttesterSlashing(
            attestation_1: IndexedAttestation(attesting_indices:
              List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE](@[j])),
            attestation_2: IndexedAttestation(attesting_indices:
              List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE](@[j])))

        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)
      withState(dag.headState.data):
        check:
          pool[].getBeaconBlockExits(state.data).attester_slashings.lenu64 ==
            min(i + 1, MAX_ATTESTER_SLASHINGS)
          pool[].getBeaconBlockExits(state.data).attester_slashings.len == 0

  test "addExitMessage/getVoluntaryExitMessage":
    for i in 0'u64 .. MAX_VOLUNTARY_EXITS + 5:
      for j in 0'u64 .. i:
        let msg = SignedVoluntaryExit(message: VoluntaryExit(validator_index: j))

        if i == 0:
          check not pool[].isSeen(msg)

        pool[].addMessage(msg)
        check: pool[].isSeen(msg)
      withState(dag.headState.data):
        check:
          pool[].getBeaconBlockExits(state.data).voluntary_exits.lenu64 ==
            min(i + 1, MAX_VOLUNTARY_EXITS)
          pool[].getBeaconBlockExits(state.data).voluntary_exits.len == 0
