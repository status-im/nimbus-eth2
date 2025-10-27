# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  chronos/timer,
  unittest2,
  ../beacon_chain/spec/beacon_time

from ../beacon_chain/spec/presets import defaultRuntimeConfig

suite "Beacon time":
  template doBasicsTest(timeParams: TimeParams) =
    let
      s0 = Slot(0)

    check:
      s0.epoch() == Epoch(0)
      s0.start_beacon_time(timeParams) == BeaconTime()
      s0.sync_committee_period() == SyncCommitteePeriod(0)

      # Roundtrip far times we treat these as "Infinity"
      FAR_FUTURE_SLOT == FAR_FUTURE_SLOT
        .epoch.start_slot()
      FAR_FUTURE_SLOT == FAR_FUTURE_SLOT
        .sync_committee_period.start_slot()
      FAR_FUTURE_EPOCH == FAR_FUTURE_EPOCH
        .start_slot().epoch()
      FAR_FUTURE_SLOT == FAR_FUTURE_SLOT
        .start_beacon_time(timeParams).slotOrZero(timeParams)
      FAR_FUTURE_PERIOD == FAR_FUTURE_PERIOD
        .start_epoch().sync_committee_period()
      FAR_FUTURE_PERIOD == FAR_FUTURE_PERIOD
        .start_slot().sync_committee_period()

      BeaconTime(ns_since_genesis: -10000000000)
        .slotOrZero(timeParams) == GENESIS_SLOT
      Slot(5).since_epoch_start() == 5
      (Epoch(42).start_slot() + 5).since_epoch_start() == 5

      Slot(5).start_beacon_time(timeParams) >
        Slot(4).start_beacon_time(timeParams)

      Slot(4).start_beacon_time(timeParams) +
        (Slot(5).start_beacon_time(timeParams) -
        Slot(4).start_beacon_time(timeParams)) ==
        Slot(5).start_beacon_time(timeParams)

      Epoch(3).start_slot.is_epoch()
      SyncCommitteePeriod(5).start_epoch().is_sync_committee_period()
      SyncCommitteePeriod(5).start_slot().is_sync_committee_period()

      Epoch(5).start_slot.sync_committee_period ==
        Epoch(5).sync_committee_period
      SyncCommitteePeriod(5).start_slot.sync_committee_period ==
        SyncCommitteePeriod(5)

    block:
      var counts = 0
      for i in countdown(SyncCommitteePeriod(1), SyncCommitteePeriod(0)):
        counts += 1
      check:
        counts == 2

  for SLOT_DURATION_MS in [5000, 6000, 12000]:
    test "basics (SLOT_DURATION_MS=" & $SLOT_DURATION_MS & ")":
      var timeParams = defaultRuntimeConfig.timeParams
      timeParams.SLOT_DURATION = milliseconds(SLOT_DURATION_MS)
      doBasicsTest timeParams

  test "Dependent slots":
    check:
      Epoch(0).proposer_dependent_slot() == Slot(0)
      Epoch(1).proposer_dependent_slot() == Epoch(1).start_slot() - 1
      Epoch(2).proposer_dependent_slot() == Epoch(2).start_slot() - 1

      Epoch(0).attester_dependent_slot() == Slot(0)
      Epoch(1).attester_dependent_slot() == Slot(0)
      Epoch(2).attester_dependent_slot() == Epoch(1).start_slot() - 1
