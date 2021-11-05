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
  ../../../beacon_chain/spec/[beaconstate, presets, state_transition_epoch],
  ../../../beacon_chain/spec/datatypes/[altair, merge],
  # Test utilities
  ../../testutil,
  ../fixtures_utils,
  ./test_fixture_rewards,
  ../../helpers/debug_state

const RootDir = SszTestsDir/const_preset/"merge"/"epoch_processing"

template runSuite(
    suiteDir, testName: string, transitionProc: untyped): untyped =
  suite "Ethereum Foundation - Merge - Epoch Processing - " & testName & preset():
    for testDir in walkDirRec(suiteDir, yieldFilter = {pcDir}, checkDir = true):

      let unitTestName = testDir.rsplit(DirSep, 1)[1]
      test testName & " - " & unitTestName & preset():
        # BeaconState objects are stored on the heap to avoid stack overflow
        type T = merge.BeaconState
        var preState {.inject.} = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, T))
        let postState = newClone(parseTest(testDir/"post.ssz_snappy", SSZ, T))
        var cache {.inject, used.} = StateCache()
        template state: untyped {.inject, used.} = preState[]
        template cfg: untyped {.inject, used.} = defaultRuntimeConfig

        transitionProc

        check:
          hash_tree_root(preState[]) == hash_tree_root(postState[])

        reportDiff(preState, postState)

# Justification & Finalization
# ---------------------------------------------------------------

const JustificationFinalizationDir = RootDir/"justification_and_finalization"/"pyspec_tests"
runSuite(JustificationFinalizationDir, "Justification & Finalization"):
  let info = altair.EpochInfo.init(state)
  process_justification_and_finalization(state, info.balances)

# Inactivity updates
# ---------------------------------------------------------------

const InactivityDir = RootDir/"inactivity_updates"/"pyspec_tests"
runSuite(InactivityDir, "Inactivity"):
  let info = altair.EpochInfo.init(state)
  process_inactivity_updates(cfg, state, info)

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
  let info = altair.EpochInfo.init(state)
  process_slashings(state, info.balances.current_epoch)

# Eth1 data reset
# ---------------------------------------------------------------

const Eth1DataResetDir = RootDir/"eth1_data_reset/"/"pyspec_tests"
runSuite(Eth1DataResetDir, "Eth1 data reset"):
  process_eth1_data_reset(state)

# Effective balance updates
# ---------------------------------------------------------------

const EffectiveBalanceUpdatesDir = RootDir/"effective_balance_updates"/"pyspec_tests"
runSuite(EffectiveBalanceUpdatesDir, "Effective balance updates"):
  process_effective_balance_updates(state)

# Slashings reset
# ---------------------------------------------------------------

const SlashingsResetDir = RootDir/"slashings_reset"/"pyspec_tests"
runSuite(SlashingsResetDir, "Slashings reset"):
  process_slashings_reset(state)

# RANDAO mixes reset
# ---------------------------------------------------------------

const RandaoMixesResetDir = RootDir/"randao_mixes_reset"/"pyspec_tests"
runSuite(RandaoMixesResetDir, "RANDAO mixes reset"):
  process_randao_mixes_reset(state)

# Historical roots update
# ---------------------------------------------------------------

const HistoricalRootsUpdateDir = RootDir/"historical_roots_update"/"pyspec_tests"
runSuite(HistoricalRootsUpdateDir, "Historical roots update"):
  process_historical_roots_update(state)

# Participation flag updates
# ---------------------------------------------------------------

const ParticipationFlagDir = RootDir/"participation_flag_updates"/"pyspec_tests"
runSuite(ParticipationFlagDir, "Participation flag updates"):
  process_participation_flag_updates(state)

# Sync committee updates
# ---------------------------------------------------------------

const SyncCommitteeDir = RootDir/"sync_committee_updates"/"pyspec_tests"
runSuite(SyncCommitteeDir, "Sync committee updates"):
  process_sync_committee_updates(state)
