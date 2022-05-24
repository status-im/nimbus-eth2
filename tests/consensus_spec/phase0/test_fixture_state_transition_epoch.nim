# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, strutils,
  # Beacon chain internals
  chronicles,
  ../../../beacon_chain/spec/state_transition_epoch,
  ../../../beacon_chain/spec/datatypes/phase0,
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ./test_fixture_rewards,
  ../../helpers/debug_state

const RootDir = SszTestsDir/const_preset/"phase0"/"epoch_processing"

template runSuite(suiteDir, testName: string, transitionProc: untyped): untyped =
  suite "EF - Phase 0 - Epoch Processing - " & testName & preset():
    for testDir in walkDirRec(suiteDir, yieldFilter = {pcDir}, checkDir = true):

      let unitTestName = testDir.rsplit(DirSep, 1)[1]
      test testName & " - " & unitTestName & preset():
        # BeaconState objects are stored on the heap to avoid stack overflow
        type T = phase0.BeaconState
        let preState {.inject.} = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, T))
        var cache {.inject, used.} = StateCache()
        var info {.inject.}: EpochInfo
        template state: untyped {.inject, used.} = preState[]
        template cfg: untyped {.inject, used.} = defaultRuntimeConfig
        init(info, preState[])

        if transitionProc.isOk:
          let postState =
            newClone(parseTest(testDir/"post.ssz_snappy", SSZ, T))
          check: hash_tree_root(preState[]) == hash_tree_root(postState[])
          reportDiff(preState, postState)
        else:
          check: not fileExists(testDir/"post.ssz_snappy")

# Justification & Finalization
# ---------------------------------------------------------------

const JustificationFinalizationDir = RootDir/"justification_and_finalization"/"pyspec_tests"
runSuite(JustificationFinalizationDir, "Justification & Finalization"):
  info.process_attestations(state, cache)
  process_justification_and_finalization(state, info.balances)
  Result[void, cstring].ok()

# Rewards & Penalties
# ---------------------------------------------------------------

# in test_fixture_rewards

# Registry updates
# ---------------------------------------------------------------

const RegistryUpdatesDir = RootDir/"registry_updates"/"pyspec_tests"
runSuite(RegistryUpdatesDir, "Registry updates"):
  process_registry_updates(cfg, state, cache)

# Slashings
# ---------------------------------------------------------------

const SlashingsDir = RootDir/"slashings"/"pyspec_tests"
runSuite(SlashingsDir, "Slashings"):
  info.process_attestations(state, cache)
  process_slashings(state, info.balances.current_epoch)
  Result[void, cstring].ok()

# Final updates
# ---------------------------------------------------------------

const Eth1DataResetDir = RootDir/"eth1_data_reset/"/"pyspec_tests"
runSuite(Eth1DataResetDir, "Eth1 data reset"):
  process_eth1_data_reset(state)
  Result[void, cstring].ok()

const EffectiveBalanceUpdatesDir = RootDir/"effective_balance_updates"/"pyspec_tests"
runSuite(EffectiveBalanceUpdatesDir, "Effective balance updates"):
  process_effective_balance_updates(state)
  Result[void, cstring].ok()

const SlashingsResetDir = RootDir/"slashings_reset"/"pyspec_tests"
runSuite(SlashingsResetDir, "Slashings reset"):
  process_slashings_reset(state)
  Result[void, cstring].ok()

const RandaoMixesResetDir = RootDir/"randao_mixes_reset"/"pyspec_tests"
runSuite(RandaoMixesResetDir, "RANDAO mixes reset"):
  process_randao_mixes_reset(state)
  Result[void, cstring].ok()

const HistoricalRootsUpdateDir = RootDir/"historical_roots_update"/"pyspec_tests"
runSuite(HistoricalRootsUpdateDir, "Historical roots update"):
  process_historical_roots_update(state)
  Result[void, cstring].ok()

const ParticipationRecordsDir = RootDir/"participation_record_updates"/"pyspec_tests"
runSuite(ParticipationRecordsDir, "Participation record updates"):
  process_participation_record_updates(state)
  Result[void, cstring].ok()
