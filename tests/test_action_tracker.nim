{.used.}

import
  unittest2,
  eth/keys,
  ../beacon_chain/validators/action_tracker

suite "subnet tracker":
  const pruneBackoffSlots = 6
  let rng = keys.newRng()

  test "should register stability subnets on attester duties":
    var tracker = ActionTracker.init(rng, pruneBackoffSlots, false)

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

    tracker.registerDuty(
      Slot(SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS), SubnetId(2), ValidatorIndex(0),
      true)
    check:
      tracker.aggregateSubnets(Slot(0)).countOnes() == 2
      tracker.aggregateSubnets(Slot(1)).countOnes() == 2

    # Guaranteed to expire
    tracker.updateSlot(
      Slot(EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION * 2 * SLOTS_PER_EPOCH))

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0

  test "don't unsubscribe and resubscribe within pruneBackoffSlots period":
    for secondActionSlot in pruneBackoffSlots..<
        pruneBackoffSlots + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS:
      var tracker = ActionTracker.init(rng, pruneBackoffSlots, false)

      check:
        tracker.stabilitySubnets(Slot(0)).countOnes() == 0
        tracker.aggregateSubnets(Slot(0)).countOnes() == 0

      tracker.registerDuty(Slot(0), SubnetId(0), ValidatorIndex(0), true)
      tracker.registerDuty(
        Slot(secondActionSlot), SubnetId(0), ValidatorIndex(0), true)

      for i in 0 .. secondActionSlot:
        check: tracker.aggregateSubnets(Slot(i)).countOnes() == 1
      check: tracker.aggregateSubnets(Slot(secondActionSlot + 1)).countOnes() == 0

  test "pruneBackoffSlots slot only":
    var tracker = ActionTracker.init(rng, pruneBackoffSlots, false)

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0

    tracker.registerDuty(
      Slot(pruneBackoffSlots), SubnetId(0), ValidatorIndex(0), true)

    for slot, subscribed in [0, 0, 0, 1, 1, 1, 1, 0]:
      check:
        tracker.aggregateSubnets(Slot(slot)).countOnes() == subscribed

  test "unsubscribe and resubscribe if pruneBackoffSlots allows":
    var tracker = ActionTracker.init(rng, pruneBackoffSlots, false)

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0

    tracker.registerDuty(Slot(0), SubnetId(0), ValidatorIndex(0), true)
    tracker.registerDuty(
      Slot(pruneBackoffSlots + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS),
      SubnetId(0), ValidatorIndex(0), true)

    for slot, subscribed in [1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0]:
      check:
        tracker.aggregateSubnets(Slot(slot)).countOnes() == subscribed

  test "first gap large enough and second not for pruneBackoffSlots":
    var tracker = ActionTracker.init(rng, pruneBackoffSlots, false)

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0

    tracker.registerDuty(Slot(0), SubnetId(0), ValidatorIndex(0), true)
    tracker.registerDuty(
      Slot(pruneBackoffSlots + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS),
      SubnetId(0), ValidatorIndex(0), true)
    tracker.registerDuty(
      Slot(2*(pruneBackoffSlots + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS)-1),
      SubnetId(0), ValidatorIndex(0), true)

    for slot, subscribed in
        [1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0]:
      check:
        tracker.aggregateSubnets(Slot(slot)).countOnes() == subscribed

  test "first gap too small and second large enough for pruneBackoffSlots":
    var tracker = ActionTracker.init(rng, pruneBackoffSlots, false)

    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0

    tracker.registerDuty(Slot(0), SubnetId(0), ValidatorIndex(0), true)
    tracker.registerDuty(
      Slot(pruneBackoffSlots + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS) - 1,
      SubnetId(0), ValidatorIndex(0), true)
    tracker.registerDuty(
      Slot(2*(pruneBackoffSlots + SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS)-1),
      SubnetId(0), ValidatorIndex(0), true)

    for slot, subscribed in
        [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0]:
      check:
        tracker.aggregateSubnets(Slot(slot)).countOnes() == subscribed
