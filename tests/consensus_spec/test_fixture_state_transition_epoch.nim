# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  ../../beacon_chain/spec/state_transition_epoch,
  ../testutil,
  ./fixtures_utils, ./os_ops,
  ./test_fixture_rewards,
  ../helpers/debug_state

from std/sequtils import mapIt, toSeq
from std/strutils import rsplit

template runSuite(
    consensusFork: static ConsensusFork,
    suiteDir, testName: string, transitionProc: untyped): untyped =
  suite "EF - " & $consensusFork & " - Epoch Processing - " & testName &
      preset():
    for testDir in walkDirRec(
        suiteDir / "pyspec_tests", yieldFilter = {pcDir}, checkDir = true):
      let unitTestName = testDir.rsplit(DirSep, 1)[1]
      test testName & " - " & unitTestName & preset():
        let preState {.inject.} = newClone(
          parseTest(testDir/"pre.ssz_snappy", SSZ, consensusFork.BeaconState))
        var cache {.inject, used.}: StateCache
        template state: untyped {.inject, used.} = preState[]
        template cfg: untyped {.inject, used.} = defaultRuntimeConfig
        when consensusFork == ConsensusFork.Phase0:
          var info {.inject.}: phase0.EpochInfo
          init(info, preState[])
          info.process_attestations(state, cache)
        else:
          var info {.inject.} = altair.EpochInfo.init(preState[])

        if transitionProc.isOk:
          let postState = newClone(
            parseTest(testDir/"post.ssz_snappy", SSZ, consensusFork.BeaconState))
          check: hash_tree_root(preState[]) == hash_tree_root(postState[])
          reportDiff(preState, postState)
        else:
          check: not fileExists(testDir/"post.ssz_snappy")

template epochProcessingSuite(consensusFork: static ConsensusFork): untyped =
  const
    RootDir = SszTestsDir/const_preset/($consensusFork)/"epoch_processing"

    JustificationFinalizationDir = RootDir/"justification_and_finalization"
    RegistryUpdatesDir           = RootDir/"registry_updates"
    SlashingsDir                 = RootDir/"slashings"
    Eth1DataResetDir             = RootDir/"eth1_data_reset"
    EffectiveBalanceUpdatesDir   = RootDir/"effective_balance_updates"
    SlashingsResetDir            = RootDir/"slashings_reset"
    RandaoMixesResetDir          = RootDir/"randao_mixes_reset"
    RewardsAndPenaltiesDir       = RootDir/"rewards_and_penalties"

  rewardsTestSuite(consensusFork)

  runSuite(consensusFork, JustificationFinalizationDir,
      "Justification & Finalization"):
    process_justification_and_finalization(state, info.balances)
    Result[void, cstring].ok()

  runSuite(consensusFork, RegistryUpdatesDir, "Registry updates"):
    process_registry_updates(cfg, state, cache)

  runSuite(consensusFork, RewardsAndPenaltiesDir, "Rewards and penalties"):
    when consensusFork == ConsensusFork.Phase0:
      process_rewards_and_penalties(state, info)
    else:
      process_rewards_and_penalties(cfg, state, info)
    Result[void, cstring].ok()

  runSuite(consensusFork, SlashingsDir, "Slashings"):
    process_slashings(state, info.balances.current_epoch)
    Result[void, cstring].ok()

  runSuite(consensusFork, Eth1DataResetDir, "Eth1 data reset"):
    process_eth1_data_reset(state)
    Result[void, cstring].ok()

  runSuite(consensusFork, EffectiveBalanceUpdatesDir,
      "Effective balance updates"):
    process_effective_balance_updates(state)
    Result[void, cstring].ok()

  runSuite(consensusFork, SlashingsResetDir, "Slashings reset"):
    process_slashings_reset(state)
    Result[void, cstring].ok()

  runSuite(consensusFork, RandaoMixesResetDir, "RANDAO mixes reset"):
    process_randao_mixes_reset(state)
    Result[void, cstring].ok()

  when consensusFork == ConsensusFork.Phase0:
    const ParticipationRecordsDir = RootDir/"participation_record_updates"

    runSuite(consensusFork, ParticipationRecordsDir,
        "Participation record updates"):
      process_participation_record_updates(state)
      Result[void, cstring].ok()
  else:
    const
      InactivityDir        = RootDir/"inactivity_updates"
      ParticipationFlagDir = RootDir/"participation_flag_updates"
      SyncCommitteeDir     = RootDir/"sync_committee_updates"

    runSuite(consensusFork, InactivityDir, "Inactivity"):
      process_inactivity_updates(cfg, state, info)
      Result[void, cstring].ok()

    runSuite(consensusFork, ParticipationFlagDir,
        "Participation flag updates"):
      process_participation_flag_updates(state)
      Result[void, cstring].ok()

    when const_preset == "minimal":
      runSuite(consensusFork, SyncCommitteeDir, "Sync committee updates"):
        process_sync_committee_updates(state)
        Result[void, cstring].ok()
    else:
      doAssert not dirExists(SyncCommitteeDir)

  when consensusFork <= ConsensusFork.Bellatrix:
    const HistoricalRootsUpdateDir = RootDir/"historical_roots_update"

    runSuite(consensusFork, HistoricalRootsUpdateDir,
        "Historical roots update"):
      process_historical_roots_update(state)
      Result[void, cstring].ok()
  else:
    const HistoricalSummariesUpdateDir = RootDir/"historical_summaries_update"

    runSuite(consensusFork, HistoricalSummariesUpdateDir,
        "Historical summaries update"):
      process_historical_summaries_update(state)

  when consensusFork >= ConsensusFork.Electra:
    const
      PendingConsolidationsDir = RootDir/"pending_consolidations"
      PendingDepositsDir       = RootDir/"pending_deposits"

    runSuite(consensusFork, PendingDepositsDir, "Pending deposits"):
      process_pending_deposits(cfg, state, cache)

    runSuite(consensusFork, PendingConsolidationsDir, "Pending consolidations"):
      process_pending_consolidations(cfg, state)

  when consensusFork >= ConsensusFork.Fulu:
    const ProposerLookaheadDir = RootDir/"proposer_lookahead"

    runSuite(consensusFork, ProposerLookaheadDir, "Proposer lookahead"):
      process_proposer_lookahead(state, cache)

  when consensusFork >= ConsensusFork.Gloas:
    const
      BuilderPendingPaymentsDir = RootDir/"builder_pending_payments"
      PendingDepositsChurnDir   = RootDir/"pending_deposits_churn"

    runSuite(consensusFork, BuilderPendingPaymentsDir,
        "Builder pending payments"):
      process_builder_pending_payments(cfg, state, cache)

    runSuite(consensusFork, PendingDepositsChurnDir,
        "Pending deposits churn"):
      process_pending_deposits(cfg, state, cache)

  when consensusFork == ConsensusFork.Gloas:
    const PtcWindowDir = RootDir/"ptc_window"

    runSuite(consensusFork, PtcWindowDir, "PTC window"):
      process_ptc_window(state, cache)
      Result[void, cstring].ok()

  const expectedDirs = block:
    var s = @[
      JustificationFinalizationDir, RegistryUpdatesDir, SlashingsDir,
      Eth1DataResetDir, EffectiveBalanceUpdatesDir, SlashingsResetDir,
      RandaoMixesResetDir, RewardsAndPenaltiesDir]
    when consensusFork == ConsensusFork.Phase0:
      s.add(ParticipationRecordsDir)
    else:
      s.add(InactivityDir)
      s.add(ParticipationFlagDir)
    when consensusFork <= ConsensusFork.Bellatrix:
      s.add(HistoricalRootsUpdateDir)
    else:
      s.add(HistoricalSummariesUpdateDir)
    when consensusFork >= ConsensusFork.Electra:
      s.add(PendingDepositsDir)
      s.add(PendingConsolidationsDir)
    when consensusFork >= ConsensusFork.Fulu:
      s.add(ProposerLookaheadDir)
    when consensusFork >= ConsensusFork.Gloas:
      s.add(BuilderPendingPaymentsDir)
      s.add(PendingDepositsChurnDir)
    when consensusFork == ConsensusFork.Gloas:
      s.add(PtcWindowDir)
    s

  when consensusFork == ConsensusFork.Phase0:
    doAssert toHashSet(mapIt(
        toSeq(walkDir(RootDir, relative = false)), it.path)) ==
      toHashSet(expectedDirs)
  else:
    doAssert (toHashSet(mapIt(
        toSeq(walkDir(RootDir, relative = false)), it.path)) -
        toHashSet([SyncCommitteeDir])) ==
      toHashSet(expectedDirs)

withAll(ConsensusFork):
  epochProcessingSuite(consensusFork)
