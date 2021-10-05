# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  # Standard library
  os, strutils,
  # Beacon chain internals
  ../../../beacon_chain/spec/[presets, state_transition_epoch],
  ../../../beacon_chain/spec/[datatypes/altair, beaconstate],
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ../test_fixture_rewards,
  ../../helpers/debug_state

from ../../../beacon_chain/spec/beaconstate import process_registry_updates
  # XXX: move to state_transition_epoch?

template runSuite(
    suiteDir, testName: string, transitionProc: untyped{ident},
    useCache, useTAB, useUPB: static bool = false): untyped =
  suite "Ethereum Foundation - Altair - Epoch Processing - " & testName & preset():
    for testDir in walkDirRec(suiteDir, yieldFilter = {pcDir}, checkDir = true):

      let unitTestName = testDir.rsplit(DirSep, 1)[1]
      test testName & " - " & unitTestName & preset():
        # BeaconState objects are stored on the heap to avoid stack overflow
        type T = altair.BeaconState
        var preState = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, T))
        let postState = newClone(parseTest(testDir/"post.ssz_snappy", SSZ, T))

        doAssert not (useCache and useTAB)
        when useCache:
          var cache = StateCache()
          when compiles(transitionProc(defaultRuntimeConfig, preState[], cache)):
            transitionProc(defaultRuntimeConfig, preState[], cache)
          else:
            transitionProc(preState[], cache)
        elif useTAB and not useUPB:
          var cache = StateCache()
          let total_active_balance = preState[].get_total_active_balance(cache)
          transitionProc(preState[], total_active_balance)
        elif useTAB and useUPB:
          var cache = StateCache()
          let
            total_active_balance = preState[].get_total_active_balance(cache)
            unslashed_participating_balances =
              preState[].get_unslashed_participating_balances()
          transitionProc(
            preState[], total_active_balance, unslashed_participating_balances)
        else:
          when compiles(transitionProc(preState[])):
            transitionProc(preState[])
          else:
            transitionProc(defaultRuntimeConfig, preState[])

        reportDiff(preState, postState)

# Justification & Finalization
# ---------------------------------------------------------------

const JustificationFinalizationDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"justification_and_finalization"/"pyspec_tests"
runSuite(JustificationFinalizationDir, "Justification & Finalization",  process_justification_and_finalization, useCache = false, useTAB = true, useUPB = true)

# Inactivity updates
# ---------------------------------------------------------------

const InactivityDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"inactivity_updates"/"pyspec_tests"
runSuite(InactivityDir, "Inactivity", process_inactivity_updates, useCache = false)

# Rewards & Penalties
# ---------------------------------------------------------------

# in test_fixture_rewards

# Registry updates
# ---------------------------------------------------------------

const RegistryUpdatesDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"registry_updates"/"pyspec_tests"
runSuite(RegistryUpdatesDir, "Registry updates",  process_registry_updates, useCache = true)

# Slashings
# ---------------------------------------------------------------

const SlashingsDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"slashings"/"pyspec_tests"
runSuite(SlashingsDir, "Slashings",  process_slashings, useCache = false, useTAB = true)

# Eth1 data reset
# ---------------------------------------------------------------

const Eth1DataResetDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"eth1_data_reset/"/"pyspec_tests"
runSuite(Eth1DataResetDir, "Eth1 data reset", process_eth1_data_reset, useCache = false)

# Effective balance updates
# ---------------------------------------------------------------

const EffectiveBalanceUpdatesDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"effective_balance_updates"/"pyspec_tests"
runSuite(EffectiveBalanceUpdatesDir, "Effective balance updates", process_effective_balance_updates, useCache = false)

# Slashings reset
# ---------------------------------------------------------------

const SlashingsResetDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"slashings_reset"/"pyspec_tests"
runSuite(SlashingsResetDir, "Slashings reset", process_slashings_reset, useCache = false)

# RANDAO mixes reset
# ---------------------------------------------------------------

const RandaoMixesResetDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"randao_mixes_reset"/"pyspec_tests"
runSuite(RandaoMixesResetDir, "RANDAO mixes reset", process_randao_mixes_reset, useCache = false)

# Historical roots update
# ---------------------------------------------------------------

const HistoricalRootsUpdateDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"historical_roots_update"/"pyspec_tests"
runSuite(HistoricalRootsUpdateDir, "Historical roots update", process_historical_roots_update, useCache = false)

# Participation flag updates
# ---------------------------------------------------------------

const ParticipationFlagDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"participation_flag_updates"/"pyspec_tests"
runSuite(ParticipationFlagDir, "Participation flag updates", process_participation_flag_updates, useCache = false)

# Sync committee updates
# ---------------------------------------------------------------

const SyncCommitteeDir = SszTestsDir/const_preset/"altair"/"epoch_processing"/"sync_committee_updates"/"pyspec_tests"
runSuite(SyncCommitteeDir, "Sync committee updates", process_sync_committee_updates, useCache = false)
