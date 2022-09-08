{.used.}

import
  unittest2,
  eth/keys,
  ../beacon_chain/validators/action_tracker

suite "subnet tracker":
  setup:
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
      tracker.knownValidators.len() == 1

    tracker.registerDuty(Slot(SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS), SubnetId(2), ValidatorIndex(0), true)
    check:
      tracker.aggregateSubnets(Slot(0)).countOnes() == 2
      tracker.aggregateSubnets(Slot(1)).countOnes() == 2
      tracker.knownValidators.len() == 1

    tracker.updateSlot(
      Slot(SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS) + KNOWN_VALIDATOR_DECAY + 1)

    check:
      # Validator should be "forgotten" if they don't register for duty
      tracker.knownValidators.len() == 0

    # Guaranteed to expire
    tracker.updateSlot(
      (Epoch(EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION * 2) + 1).start_slot() +
      SUBNET_SUBSCRIPTION_LEAD_TIME_SLOTS + KNOWN_VALIDATOR_DECAY + 1)


    check:
      tracker.stabilitySubnets(Slot(0)).countOnes() == 0
      tracker.aggregateSubnets(Slot(0)).countOnes() == 0
