# beacon_chain
# Copyright (c) 2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import std/unittest
import chronicles, chronos, testutil
import ../beacon_chain/spec/[datatypes, presets]
import ../beacon_chain/exit_pool
import ../beacon_chain/block_pools/chain_dag

proc getExitPool(): auto =
  let chainDag =
    init(ChainDAGRef, defaultRuntimePreset, makeTestDB(SLOTS_PER_EPOCH * 3))
  newClone(ExitPool.init(chainDag, QuarantineRef()))

suiteReport "Exit pool testing suite":
  setup:
    let pool = getExitPool()
  timedTest "addExitMessage/getProposerSlashingMessage":
    for i in 0'u64 .. MAX_PROPOSER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        pool.proposer_slashings.addExitMessage(j,
          ProposerSlashing(), MAX_PROPOSER_SLASHINGS)
      check:
        pool[].getProposerSlashingsForBlock().lenu64 ==
          min(i + 1, MAX_PROPOSER_SLASHINGS)
        pool[].getProposerSlashingsForBlock().len == 0

  timedTest "addExitMessage/getAttesterSlashingMessage":
    for i in 0'u64 .. MAX_ATTESTER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        pool.attester_slashings.addExitMessage((@[j], @[j]),
          AttesterSlashing(), MAX_ATTESTER_SLASHINGS)
      check:
        pool[].getAttesterSlashingsForBlock().lenu64 ==
          min(i + 1, MAX_ATTESTER_SLASHINGS)
        pool[].getAttesterSlashingsForBlock().len == 0

  timedTest "addExitMessage/getVoluntaryExitMessage":
    for i in 0'u64 .. MAX_VOLUNTARY_EXITS + 5:
      for j in 0'u64 .. i:
        pool.voluntary_exits.addExitMessage(j,
          SignedVoluntaryExit(), MAX_VOLUNTARY_EXITS)
      check:
        pool[].getVoluntaryExitsForBlock().lenu64 ==
          min(i + 1, MAX_VOLUNTARY_EXITS)
        pool[].getProposerSlashingsForBlock().len == 0

  timedTest "addExitMessage/removeExitMessage/getProposerSlashingMessages":
    for i in 0'u64 .. MAX_PROPOSER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        pool.proposer_slashings.addExitMessage(j,
          ProposerSlashing(), MAX_PROPOSER_SLASHINGS)
      pool[].removeBeaconBlockIncludedMessages(
        BeaconBlockBody(
          proposer_slashings: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS](
            @[ProposerSlashing(
              signed_header_1: SignedBeaconBlockHeader(message:
                BeaconBlockHeader(proposer_index: 0'u64)))])))
      check:
        pool[].getProposerSlashingsForBlock().lenu64 ==
          min(i, MAX_PROPOSER_SLASHINGS)
        pool[].getProposerSlashingsForBlock().len == 0

  timedTest "addExitMessage/removeExitMessage/getAttesterSlashingMessages":
    for i in 0'u64 .. MAX_ATTESTER_SLASHINGS + 5:
      for j in 0'u64 .. i:
        pool.attester_slashings.addExitMessage((@[j], @[j]),
          AttesterSlashing(), MAX_ATTESTER_SLASHINGS)
      pool[].removeBeaconBlockIncludedMessages(
        BeaconBlockBody(
          attester_slashings: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS](
            @[AttesterSlashing(
              attestation_1: IndexedAttestation(attesting_indices:
                List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE](@[0'u64])),
              attestation_2: IndexedAttestation(attesting_indices:
                List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE](@[0'u64])))])))
      check:
        pool[].getAttesterSlashingsForBlock().lenu64 ==
          min(i, MAX_ATTESTER_SLASHINGS)
        pool[].getAttesterSlashingsForBlock().len == 0

  timedTest "addExitMessage/removeExitMessage/getVoluntaryExitMessages":
    for i in 0'u64 .. MAX_VOLUNTARY_EXITS + 5:
      for j in 0'u64 .. i:
        pool.voluntary_exits.addExitMessage(j,
          SignedVoluntaryExit(), MAX_VOLUNTARY_EXITS)
      pool[].removeBeaconBlockIncludedMessages(
        BeaconBlockBody(
          voluntary_exits: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS](
            @[SignedVoluntaryExit(
              message: VoluntaryExit(validator_index: 0'u64))])))
      check:
        pool[].getVoluntaryExitsForBlock().lenu64 ==
          min(i, MAX_VOLUNTARY_EXITS)
        pool[].getProposerSlashingsForBlock().len == 0
