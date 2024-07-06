# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Status internals
  chronicles,
  # Beacon chain internals
  ../../../beacon_chain/spec/[presets, state_transition_epoch],
  ../../../beacon_chain/spec/datatypes/altair,
  # Test utilities
  ../../testutil,
  ../fixtures_utils, ../os_ops,
  ./test_fixture_rewards,
  ../../helpers/debug_state

from std/sequtils import mapIt, toSeq
from std/strutils import rsplit
from ../../../beacon_chain/spec/datatypes/electra import BeaconState
from ../../teststateutil import checkPerValidatorBalanceCalc

const
  RootDir = SszTestsDir/const_preset/"electra"/"epoch_processing"

  JustificationFinalizationDir = RootDir/"justification_and_finalization"
  InactivityDir =                RootDir/"inactivity_updates"
  RegistryUpdatesDir =           RootDir/"registry_updates"
  SlashingsDir =                 RootDir/"slashings"
  Eth1DataResetDir =             RootDir/"eth1_data_reset"
  EffectiveBalanceUpdatesDir =   RootDir/"effective_balance_updates"
  SlashingsResetDir =            RootDir/"slashings_reset"
  RandaoMixesResetDir =          RootDir/"randao_mixes_reset"
  ParticipationFlagDir =         RootDir/"participation_flag_updates"
  SyncCommitteeDir =             RootDir/"sync_committee_updates"
  RewardsAndPenaltiesDir =       RootDir/"rewards_and_penalties"
  HistoricalSummariesUpdateDir = RootDir/"historical_summaries_update"
  PendingBalanceDepositsDir =    RootDir/"pending_balance_deposits"
  PendingConsolidationsDir =     RootDir/"pending_consolidations"

doAssert (toHashSet(mapIt(toSeq(walkDir(RootDir, relative = false)), it.path)) -
    toHashSet([SyncCommitteeDir])) ==
  toHashSet([
    JustificationFinalizationDir, InactivityDir, RegistryUpdatesDir,
    SlashingsDir, Eth1DataResetDir, EffectiveBalanceUpdatesDir,
    SlashingsResetDir, RandaoMixesResetDir, ParticipationFlagDir,
    RewardsAndPenaltiesDir, HistoricalSummariesUpdateDir,
    PendingBalanceDepositsDir, PendingConsolidationsDir])

template runSuite(
    suiteDir, testName: string, transitionProc: untyped): untyped =
  suite "EF - Electra - Epoch Processing - " & testName & preset():
    for testDir in walkDirRec(
        suiteDir / "pyspec_tests", yieldFilter = {pcDir}, checkDir = true):
      let unitTestName = testDir.rsplit(DirSep, 1)[1]
      test testName & " - " & unitTestName & preset():
        # BeaconState objects are stored on the heap to avoid stack overflow
        type T = electra.BeaconState
        let preState {.inject.} = newClone(parseTest(testDir/"pre.ssz_snappy", SSZ, T))
        var cache {.inject, used.} = StateCache()
        template state: untyped {.inject, used.} = preState[]
        template cfg: untyped {.inject, used.} = defaultRuntimeConfig

        if transitionProc.isOk:
          let postState =
            newClone(parseTest(testDir/"post.ssz_snappy", SSZ, T))
          check: hash_tree_root(preState[]) == hash_tree_root(postState[])
          reportDiff(preState, postState)
        else:
          check: not fileExists(testDir/"post.ssz_snappy")

# Justification & Finalization
# ---------------------------------------------------------------
runSuite(JustificationFinalizationDir, "Justification & Finalization"):
  let info = altair.EpochInfo.init(state)
  check checkPerValidatorBalanceCalc(state)
  process_justification_and_finalization(state, info.balances)
  Result[void, cstring].ok()

# Inactivity updates
# ---------------------------------------------------------------
runSuite(InactivityDir, "Inactivity"):
  let info = altair.EpochInfo.init(state)
  check checkPerValidatorBalanceCalc(state)
  process_inactivity_updates(cfg, state, info)
  Result[void, cstring].ok()

# Rewards & Penalties
# ---------------------------------------------------------------
runSuite(RewardsAndPenaltiesDir, "Rewards and penalties"):
  var info = altair.EpochInfo.init(state)
  process_rewards_and_penalties(cfg, state, info)
  Result[void, cstring].ok()

# rest in test_fixture_rewards

# Registry updates
# ---------------------------------------------------------------
runSuite(RegistryUpdatesDir, "Registry updates"):
  process_registry_updates(cfg, state, cache)

# Slashings
# ---------------------------------------------------------------
runSuite(SlashingsDir, "Slashings"):
  let info = altair.EpochInfo.init(state)
  process_slashings(state, info.balances.current_epoch)
  Result[void, cstring].ok()

# Eth1 data reset
# ---------------------------------------------------------------
runSuite(Eth1DataResetDir, "Eth1 data reset"):
  process_eth1_data_reset(state)
  Result[void, cstring].ok()

# Effective balance updates
# ---------------------------------------------------------------
runSuite(EffectiveBalanceUpdatesDir, "Effective balance updates"):
  process_effective_balance_updates(state)
  Result[void, cstring].ok()

# Slashings reset
# ---------------------------------------------------------------
runSuite(SlashingsResetDir, "Slashings reset"):
  process_slashings_reset(state)
  Result[void, cstring].ok()

# RANDAO mixes reset
# ---------------------------------------------------------------
runSuite(RandaoMixesResetDir, "RANDAO mixes reset"):
  process_randao_mixes_reset(state)
  Result[void, cstring].ok()

# Historical roots update
# ---------------------------------------------------------------
runSuite(HistoricalSummariesUpdateDir, "Historical summaries update"):
  process_historical_summaries_update(state)

# Participation flag updates
# ---------------------------------------------------------------
runSuite(ParticipationFlagDir, "Participation flag updates"):
  process_participation_flag_updates(state)
  Result[void, cstring].ok()

# Pending balance deposits
# ---------------------------------------------------------------
runSuite(PendingBalanceDepositsDir, "Pending balance deposits"):
  process_pending_balance_deposits(cfg, state, cache)

# Pending consolidations
# ---------------------------------------------------------------
runSuite(PendingConsolidationsDir, "Pending consolidations"):
  process_pending_consolidations(cfg, state)

# Sync committee updates
# ---------------------------------------------------------------

# These are only for minimal, not mainnet
when const_preset == "minimal":
  runSuite(SyncCommitteeDir, "Sync committee updates"):
    process_sync_committee_updates(state)
    Result[void, cstring].ok()
else:
  doAssert not dirExists(SyncCommitteeDir)