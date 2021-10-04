{.used.}

import
  unittest2,
  eth/keys,
  ../beacon_chain/validators/action_tracker,
  testblockutil

suite "subnet tracker":
  let rng = keys.newRng()

  test "should register stability subnets on attester duties":
    var tracker = ActionTracker.init(rng, false)

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0

    tracker.registerDuty(Slot(0), SubnetId(0), ValidatorIndex(0), true)

    tracker.updateSlot(Slot(0))

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 1
      tracker.aggregateSubnets(Slot(0)).countOnes() == 1
      tracker.aggregateSubnets(Slot(1)).countOnes() == 0

    tracker.registerDuty(Slot(1), SubnetId(1), ValidatorIndex(0), true)
    check:
      tracker.aggregateSubnets(Slot(0)).countOnes() == 2
      tracker.aggregateSubnets(Slot(1)).countOnes() == 1

    # Guaranteed to expire
    tracker.updateSlot(
      Slot(EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION * 2 * SLOTS_PER_EPOCH))

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0
