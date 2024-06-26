# beacon_chain
# Copyright (c) 2021-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/[beaconstate, helpers, signatures],
  ../beacon_chain/consensus_object_pools/sync_committee_msg_pool,
  ./testblockutil

func aggregate(sigs: openArray[CookedSig]): CookedSig =
  var agg {.noinit.}: AggregateSignature
  agg.init sigs[0]
  for i in 1 ..< sigs.len:
    agg.aggregate sigs[i]
  agg.finish

suite "Sync committee pool":
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = block:
        var res = defaultRuntimeConfig
        res.ALTAIR_FORK_EPOCH = 0.Epoch
        res.BELLATRIX_FORK_EPOCH = 20.Epoch
        res
    var pool = SyncCommitteeMsgPool.init(rng, cfg)

  test "An empty pool is safe to use":
    let headBid =
      BlockId(slot: Slot(1), root: eth2digest(@[1.byte, 2, 3]))

    var outContribution: SyncCommitteeContribution
    let success = pool.produceContribution(
      Slot(1),
      headBid,
      SyncSubcommitteeIndex(0),
      outContribution)

    check(success == false)

    let aggregate = pool.produceSyncAggregate(headBid, headBid.slot + 1)

    check:
      aggregate.sync_committee_bits.isZeros
      aggregate.sync_committee_signature == ValidatorSig.infinity

  test "An empty pool is safe to prune":
    pool.pruneData(Slot(0))

  test "An empty pool is safe to prune 2":
    pool.pruneData(Slot(10000))

  test "Missed slots across sync committee period boundary":
    let
      genesis_validators_root = eth2digest(@[5.byte, 6, 7])

      privkey1 = MockPrivKeys[1.ValidatorIndex]
      privkey2 = MockPrivKeys[2.ValidatorIndex]

      nextPeriod = cfg.BELLATRIX_FORK_EPOCH.sync_committee_period + 1

      bid1 = BlockId(
        slot: Slot(nextPeriod.start_slot - 2),  # Committee based on `slot + 1`
        root: eth2digest(@[1.byte]))

      sig1 = get_sync_committee_message_signature(
        bellatrixFork(cfg), genesis_validators_root,
        bid1.slot, bid1.root, privkey1)
      sig2 = get_sync_committee_message_signature(
        bellatrixFork(cfg), genesis_validators_root,
        bid1.slot + 1, bid1.root, privkey2)

    pool.addSyncCommitteeMessage(
      bid1.slot, bid1, 1, sig1, SyncSubcommitteeIndex(0), @[1'u64])
    pool.addSyncCommitteeMessage(
      # Same participant index in next period represents different validator
      bid1.slot + 1, bid1, 2, sig2, SyncSubcommitteeIndex(0), @[1'u64])

    var contribution: SyncCommitteeContribution
    let success = pool.produceContribution(
      bid1.slot + 1, bid1, SyncSubcommitteeIndex(0), contribution)
    check:
      success
      contribution.slot == bid1.slot + 1
      contribution.beacon_block_root == bid1.root
      contribution.subcommittee_index == SyncSubcommitteeIndex(0).uint64
      contribution.aggregation_bits.countOnes == 1
      contribution.aggregation_bits[1] == true
      contribution.signature == sig2.toValidatorSig

  test "Missed slots across fork transition":
    let
      genesis_validators_root = eth2digest(@[5.byte, 6, 7])

      privkey1 = MockPrivKeys[1.ValidatorIndex]
      privkey2 = MockPrivKeys[1.ValidatorIndex]

      bid1 = BlockId(
        slot: cfg.BELLATRIX_FORK_EPOCH.start_slot - 1,
        root: eth2digest(@[1.byte]))

      sig1 = get_sync_committee_message_signature(
        altairFork(cfg), genesis_validators_root,
        bid1.slot, bid1.root, privkey1)
      sig2 = get_sync_committee_message_signature(
        bellatrixFork(cfg), genesis_validators_root,
        bid1.slot + 1, bid1.root, privkey2)

    pool.addSyncCommitteeMessage(
      bid1.slot, bid1, 1, sig1, SyncSubcommitteeIndex(0), @[1'u64])
    pool.addSyncCommitteeMessage(
      bid1.slot + 1, bid1, 2, sig2, SyncSubcommitteeIndex(0), @[2'u64])

    var contribution: SyncCommitteeContribution
    let success = pool.produceContribution(
      bid1.slot + 1, bid1, SyncSubcommitteeIndex(0), contribution)
    check:
      success
      contribution.slot == bid1.slot + 1
      contribution.beacon_block_root == bid1.root
      contribution.subcommittee_index == SyncSubcommitteeIndex(0).uint64
      contribution.aggregation_bits.countOnes == 1
      contribution.aggregation_bits[2] == true
      contribution.signature == sig2.toValidatorSig

  test "isSeen":
    let
      fork = altairFork(cfg)
      genesis_validators_root = eth2digest(@[5.byte, 6, 7])

      privkey1 = MockPrivKeys[1.ValidatorIndex]

      bid1 = BlockId(slot: Slot(100), root: eth2digest(@[1.byte]))
      bid2 = BlockId(slot: Slot(101), root: eth2digest(@[1.byte, 2]))

      sig1 = get_sync_committee_message_signature(
        fork, genesis_validators_root, bid2.slot, bid1.root, privkey1)
      sig2 = get_sync_committee_message_signature(
        fork, genesis_validators_root, bid2.slot, bid2.root, privkey1)

      msg1 = SyncCommitteeMessage(
        slot: bid2.slot,
        beacon_block_root: bid1.root,
        validator_index: 1,
        signature: sig1.toValidatorSig)
      msg2 = SyncCommitteeMessage(
        slot: bid2.slot,
        beacon_block_root: bid2.root,
        validator_index: 1,
        signature: sig2.toValidatorSig)

    check:
      not pool.isSeen(msg1, SyncSubcommitteeIndex(0), bid2)
      not pool.isSeen(msg2, SyncSubcommitteeIndex(0), bid2)

    pool.addSyncCommitteeMessage(
      bid2.slot, bid1, 1, sig1, SyncSubcommitteeIndex(0), @[1'u64])
    check:
      pool.isSeen(msg1, SyncSubcommitteeIndex(0), bid2)
      not pool.isSeen(msg2, SyncSubcommitteeIndex(0), bid2)

    pool.addSyncCommitteeMessage(
      bid2.slot, bid2, 1, sig1, SyncSubcommitteeIndex(0), @[1'u64])
    check:
      pool.isSeen(msg1, SyncSubcommitteeIndex(0), bid2)
      pool.isSeen(msg2, SyncSubcommitteeIndex(0), bid2)

  test "Aggregating votes":
    let
      fork = altairFork(cfg)
      genesis_validators_root = eth2digest(@[5.byte, 6, 7])

      privkey1 = MockPrivKeys[1.ValidatorIndex]
      privkey2 = MockPrivKeys[2.ValidatorIndex]
      privkey3 = MockPrivKeys[3.ValidatorIndex]
      privkey4 = MockPrivKeys[4.ValidatorIndex]

      bid1 = BlockId(slot: Slot(100), root: eth2digest(@[1.byte]))
      bid2 = BlockId(slot: Slot(101), root: eth2digest(@[1.byte, 2]))
      bid3 = BlockId(slot: Slot(101), root: eth2digest(@[1.byte, 2, 3]))

      subcommittee1 = SyncSubcommitteeIndex(0)
      subcommittee2 = SyncSubcommitteeIndex(1)

      sig1 = get_sync_committee_message_signature(
        fork, genesis_validators_root, bid1.slot, bid1.root, privkey1)
      sig2 = get_sync_committee_message_signature(
        fork, genesis_validators_root, bid2.slot, bid2.root, privkey1)
      sig3 = get_sync_committee_message_signature(
        fork, genesis_validators_root, bid3.slot, bid3.root, privkey1)
      sig4 = get_sync_committee_message_signature(
        fork, genesis_validators_root, bid3.slot, bid2.root, privkey1)

    # Inserting sync committee messages
    #
    pool.addSyncCommitteeMessage(
      bid1.slot, bid1, 1, sig1, subcommittee1, @[1'u64])
    pool.addSyncCommitteeMessage(
      bid1.slot, bid1, 2, sig2, subcommittee1, @[10'u64])
    pool.addSyncCommitteeMessage(
      bid2.slot, bid1, 3, sig3, subcommittee2, @[7'u64])
    pool.addSyncCommitteeMessage(
      bid2.slot, bid2, 4, sig4, subcommittee2, @[3'u64])

    # Insert a duplicate message (this should be handled gracefully)
    pool.addSyncCommitteeMessage(
      bid1.slot, bid1, 1, sig1, subcommittee1, @[1'u64])

    # Producing contributions
    #
    block:
      # Checking a committee where there was no activity:
      var outContribution: SyncCommitteeContribution
      let success = pool.produceContribution(
        bid2.slot,
        bid2,
        subcommittee1,
        outContribution)

      check:
        not success

    block:
      # Checking a committee where 2 signatures should have been aggregated:
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        bid1.slot,
        bid1,
        subcommittee1,
        contribution)

      let sig = aggregate [sig1, sig2]
      check:
        success
        contribution.slot == bid1.slot
        contribution.beacon_block_root == bid1.root
        contribution.subcommittee_index == subcommittee1.uint64
        contribution.aggregation_bits.countOnes == 2
        contribution.aggregation_bits[1] == true
        contribution.aggregation_bits[8] == false
        contribution.aggregation_bits[10] == true
        contribution.signature == sig.toValidatorSig

      check:
        not pool.covers(contribution, bid1)

      pool.addContribution(outContribution, bid1, sig)
      check:
        pool.isSeen(outContribution.message)
        pool.covers(contribution, bid1)

    block:
      # Checking a committee with a signle participant:
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        bid1.slot,
        bid1,
        subcommittee2,
        contribution)

      check:
        success
        contribution.slot == bid1.slot
        contribution.beacon_block_root == bid1.root
        contribution.subcommittee_index == subcommittee2.uint64
        contribution.aggregation_bits.countOnes == 1
        contribution.aggregation_bits[7] == true
        contribution.signature == sig3.toValidatorSig

      check:
        not pool.covers(contribution, bid1)
      pool.addContribution(outContribution, bid1, sig3)
      check:
        pool.isSeen(outContribution.message)
        pool.covers(contribution, bid1)

    block:
      # Checking another committee with a signle participant
      # voting for a different block:
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        bid2.slot,
        bid2,
        subcommittee2,
        contribution)

      check:
        success
        contribution.slot == bid2.slot
        contribution.beacon_block_root == bid2.root
        contribution.subcommittee_index == subcommittee2.uint64
        contribution.aggregation_bits.countOnes == 1
        contribution.aggregation_bits[3] == true
        contribution.signature == sig4.toValidatorSig

      check:
        not pool.covers(contribution, bid2)
      pool.addContribution(outContribution, bid2, sig4)

      check:
        pool.isSeen(outContribution.message)
        pool.covers(contribution, bid2)

    block:
      # Checking a block root nobody voted for
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        bid3.slot,
        bid3,
        subcommittee2,
        contribution)

      check:
        not success

    # Obtaining a SyncAggregate
    #
    block:
      # Checking for a block that got no votes
      let aggregate = pool.produceSyncAggregate(bid3, bid3.slot + 1)
      check:
        aggregate.sync_committee_bits.isZeros
        aggregate.sync_committee_signature == ValidatorSig.infinity

    block:
      # Checking for a block that got votes from 1 committee
      let aggregate = pool.produceSyncAggregate(bid2, bid2.slot + 1)
      check:
        aggregate.sync_committee_bits.countOnes == 1
        aggregate.sync_committee_signature == sig4.toValidatorSig

    block:
      # Checking for a block that got votes from 2 committees
      let aggregate = pool.produceSyncAggregate(bid1, bid1.slot + 1)
      let sig = aggregate [sig1, sig2, sig3]
      check:
        aggregate.sync_committee_bits.countOnes == 3
        aggregate.sync_committee_signature == sig.toValidatorSig

    # Pruning the data
    #
    pool.pruneData(Slot(200), force = true)

    block:
      # After pruning, all votes are gone
      var outContribution: SyncCommitteeContribution
      let success = pool.produceContribution(
        bid1.slot,
        bid1,
        subcommittee1,
        outContribution)

      check:
        not success

      let aggregate = pool.produceSyncAggregate(bid2, bid2.slot + 1)
      check:
        aggregate.sync_committee_bits.isZeros
        aggregate.sync_committee_signature == ValidatorSig.infinity
