# beacon_chain
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import chronicles, chronos
import eth/keys
import ../beacon_chain/spec/[datatypes, presets]
import ../beacon_chain/consensus_object_pools/[block_quarantine, blockchain_dag, exit_pool]
import "."/[testutil, testdbutil]

proc getExitPool(): auto =
  let chainDag =
    init(ChainDAGRef, defaultRuntimePreset, makeTestDB(SLOTS_PER_EPOCH * 3))
  newClone(ExitPool.init(chainDag, QuarantineRef.init(keys.newRng())))

suite "Exit pool testing suite":
  setup:
    let pool = getExitPool()
  test "addExitMessage/getProposerSlashingMessage":
    for i in 0'u64 .. MAX_PROPOSER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        pool.proposer_slashings.addExitMessage(
          ProposerSlashing(), MAX_PROPOSER_SLASHINGS)
      check:
        pool[].getProposerSlashingsForBlock().lenu64 ==
          min(i + 1, MAX_PROPOSER_SLASHINGS)
        pool[].getProposerSlashingsForBlock().len == 0

  test "addExitMessage/getAttesterSlashingMessage":
    for i in 0'u64 .. MAX_ATTESTER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        pool.attester_slashings.addExitMessage(
          AttesterSlashing(
            attestation_1: IndexedAttestation(attesting_indices:
              List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE](@[0'u64])),
            attestation_2: IndexedAttestation(attesting_indices:
              List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE](@[0'u64]))),
          MAX_ATTESTER_SLASHINGS)
      check:
        pool[].getAttesterSlashingsForBlock().lenu64 ==
          min(i + 1, MAX_ATTESTER_SLASHINGS)
        pool[].getAttesterSlashingsForBlock().len == 0

  test "addExitMessage/getVoluntaryExitMessage":
    for i in 0'u64 .. MAX_VOLUNTARY_EXITS + 5:
      for j in 0'u64 .. i:
        pool.voluntary_exits.addExitMessage(
          SignedVoluntaryExit(), MAX_VOLUNTARY_EXITS)
      check:
        pool[].getVoluntaryExitsForBlock().lenu64 ==
          min(i + 1, MAX_VOLUNTARY_EXITS)
        pool[].getProposerSlashingsForBlock().len == 0
