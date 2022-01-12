{.used.}

import
  unittest2,

  ../beacon_chain/spec/beacon_time

suite "Beacon time":
  test "basics":
    let
      s0 = Slot(0)

    check:
      s0.epoch() == Epoch(0)
      s0.start_beacon_time() == BeaconTime()
      s0.sync_committee_period() == SyncCommitteePeriod(0)

      # Roundtrip far times we treat these as "Infinitiy"
      FAR_FUTURE_SLOT.epoch.start_slot() == FAR_FUTURE_SLOT
      FAR_FUTURE_EPOCH.start_slot().epoch() == FAR_FUTURE_EPOCH
      FAR_FUTURE_SLOT.start_beacon_time().slotOrZero() == FAR_FUTURE_SLOT
      FAR_FUTURE_PERIOD.start_epoch().sync_committee_period() == FAR_FUTURE_PERIOD

      BeaconTime(ns_since_genesis: -10000000000).slotOrZero == Slot(0)
      Slot(5).since_epoch_start() == 5
      (Epoch(42).start_slot() + 5).since_epoch_start() == 5

      Slot(5).start_beacon_time() > Slot(4).start_beacon_time()

      Slot(4).start_beacon_time() +
        (Slot(5).start_beacon_time() - Slot(4).start_beacon_time()) ==
        Slot(5).start_beacon_time()

      Epoch(3).start_slot.is_epoch()
      SyncCommitteePeriod(5).start_epoch().is_sync_committee_period()

      Epoch(5).start_slot.sync_committee_period ==
        Epoch(5).sync_committee_period
