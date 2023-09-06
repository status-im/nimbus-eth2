# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ../beacon_chain/validators/action_tracker

suite "subnet tracker":
  setup:
    let rng = HmacDrbgContext.new()

  test "should register sync committee duties":
    var
      tracker = ActionTracker.init(default(UInt256), false)
      pk0 = ValidatorPubKey.fromHex("0xb4102a1f6c80e5c596a974ebd930c9f809c3587dc4d1d3634b77ff66db71e376dbc86c3252c6d140ce031f4ec6167798").get()
      pk1 = ValidatorPubKey.fromHex("0xa00d2954717425ce047e0928e5f4ec7c0e3bbe1058db511303fd659770ddace686ee2e22ac180422e516f4c503eb2228").get()

    check:
      not tracker.hasSyncDuty(pk0, Epoch(1024))

    tracker.lastSyncUpdate = Opt.some(SyncCommitteePeriod(42))
    tracker.registerSyncDuty(pk0, Epoch(1024))
    check:
      tracker.lastSyncUpdate.isNone()
      not tracker.hasSyncDuty(pk0, Epoch(1024))
      not tracker.hasSyncDuty(pk1, Epoch(1023))
      tracker.hasSyncDuty(pk0, Epoch(1023))

    tracker.registerSyncDuty(pk0, Epoch(1022))

    check: # Should not overwrite longer duties
      tracker.hasSyncDuty(pk0, Epoch(1023))

    tracker.registerSyncDuty(pk0, Epoch(1025))
    check: # Should update existing duties
      tracker.hasSyncDuty(pk0, Epoch(1024))

    tracker.updateSlot(Epoch(1025).start_slot)

    check: # should prune old duties on updateSlot
      not tracker.hasSyncDuty(pk0, Epoch(1024))

    tracker.registerSyncDuty(pk0, Epoch(1025))

    check: # should not add old duties
      not tracker.hasSyncDuty(pk0, Epoch(1024))
