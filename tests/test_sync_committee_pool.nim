{.used.}

import
  unittest2,
  ../beacon_chain/spec/[beaconstate, helpers, signatures],
  ../beacon_chain/consensus_object_pools/sync_committee_msg_pool,
  ./testblockutil

func aggregate(sigs: openarray[CookedSig]): CookedSig =
  var agg {.noInit.}: AggregateSignature
  agg.init sigs[0]
  for i in 1 ..< sigs.len:
    agg.aggregate sigs[i]
  agg.finish

suite "Sync committee pool":
  setup:
    var pool = SyncCommitteeMsgPool.init()

  test "An empty pool is safe to use":
    let headRoot = eth2digest(@[1.byte, 2, 3])

    var outContribution: SyncCommitteeContribution
    let success = pool.produceContribution(
      Slot(1),
      headRoot,
      SyncSubcommitteeIndex(0),
      outContribution)

    check(success == false)

    let aggregate = pool.produceSyncAggregate(headRoot)

    check:
      aggregate.sync_committee_bits.isZeros
      aggregate.sync_committee_signature == ValidatorSig.infinity

  test "An empty pool is safe to prune":
    pool.pruneData(Slot(0))

  test "An empty pool is safe to prune 2":
    pool.pruneData(Slot(10000))

  test "Aggregating votes":
    let
      fork = altairFork(defaultRuntimeConfig)
      genesisValidatorsRoot = eth2digest(@[5.byte, 6, 7])

      privkey1 = MockPrivKeys[1.ValidatorIndex]
      privkey2 = MockPrivKeys[2.ValidatorIndex]
      privkey3 = MockPrivKeys[3.ValidatorIndex]
      privkey4 = MockPrivKeys[4.ValidatorIndex]

      root1 = eth2digest(@[1.byte])
      root2 = eth2digest(@[1.byte, 2])
      root3 = eth2digest(@[1.byte, 2, 3])

      root1Slot = Slot(100)
      root2Slot = Slot(101)
      root3Slot = Slot(101)

      subcommittee1 = SyncSubcommitteeIndex(0)
      subcommittee2 = SyncSubcommitteeIndex(1)

      sig1 = blsSign(privkey1, sync_committee_msg_signing_root(
        fork, root1Slot.epoch, genesisValidatorsRoot, root1).data)

      sig2 = blsSign(privkey2, sync_committee_msg_signing_root(
        fork, root2Slot.epoch, genesisValidatorsRoot, root1).data)

      sig3 = blsSign(privkey3, sync_committee_msg_signing_root(
        fork, root3Slot.epoch, genesisValidatorsRoot, root1).data)

      sig4 = blsSign(privkey4, sync_committee_msg_signing_root(
        fork, root3Slot.epoch, genesisValidatorsRoot, root2).data)

    # Inserting sync committee messages
    #
    pool.addSyncCommitteeMsg(root1Slot, root1, 1, sig1, subcommittee1, [1'u64])
    pool.addSyncCommitteeMsg(root1Slot, root1, 2, sig2, subcommittee1, [10'u64])
    pool.addSyncCommitteeMsg(root2Slot, root1, 3, sig3, subcommittee2, [7'u64])
    pool.addSyncCommitteeMsg(root2Slot, root2, 4, sig4, subcommittee2, [3'u64])

    # Insert a duplicate message (this should be handled gracefully)
    pool.addSyncCommitteeMsg(root1Slot, root1, 1, sig1, subcommittee1, [1'u64])

    # Producing contributions
    #
    block:
      # Checking a committee where there was no activity:
      var outContribution: SyncCommitteeContribution
      let success = pool.produceContribution(
        root2Slot,
        root2,
        subcommittee1,
        outContribution)

      check:
        not success

    block:
      # Checking a committee where 2 signatures should have been aggregated:
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        root1Slot,
        root1,
        subcommittee1,
        contribution)

      let expectedSig = aggregate [sig1, sig2]
      check:
        success
        contribution.slot == root1Slot
        contribution.beacon_block_root == root1
        contribution.subcommittee_index == subcommittee1.uint64
        contribution.aggregation_bits.countOnes == 2
        contribution.aggregation_bits[1] == true
        contribution.aggregation_bits[8] == false
        contribution.aggregation_bits[10] == true
        contribution.signature == expectedSig.toValidatorSig

      pool.addSyncContribution(outContribution, expectedSig)
      check: pool.isSeen(outContribution.message)

    block:
      # Checking a committee with a signle participant:
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        root1Slot,
        root1,
        subcommittee2,
        contribution)

      check:
        success
        contribution.slot == root1Slot
        contribution.beacon_block_root == root1
        contribution.subcommittee_index == subcommittee2.uint64
        contribution.aggregation_bits.countOnes == 1
        contribution.aggregation_bits[7] == true
        contribution.signature == sig3.toValidatorSig

      pool.addSyncContribution(outContribution, sig3)
      check: pool.isSeen(outContribution.message)

    block:
      # Checking another committee with a signle participant
      # voting for a different block:
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        root2Slot,
        root2,
        subcommittee2,
        contribution)

      check:
        success
        contribution.slot == root2Slot
        contribution.beacon_block_root == root2
        contribution.subcommittee_index == subcommittee2.uint64
        contribution.aggregation_bits.countOnes == 1
        contribution.aggregation_bits[3] == true
        contribution.signature == sig4.toValidatorSig

      pool.addSyncContribution(outContribution, sig4)
      check: pool.isSeen(outContribution.message)

    block:
      # Checking a block root nobody voted for
      var outContribution: SignedContributionAndProof
      template contribution: untyped = outContribution.message.contribution
      let success = pool.produceContribution(
        root3Slot,
        root3,
        subcommittee2,
        contribution)

      check:
        not success

    # Obtaining a SyncAggregate
    #
    block:
      # Checking for a block that got no votes
      let aggregate = pool.produceSyncAggregate(root3)
      check:
        aggregate.sync_committee_bits.isZeros
        aggregate.sync_committee_signature == ValidatorSig.infinity

    block:
      # Checking for a block that got votes from 1 committee
      let aggregate = pool.produceSyncAggregate(root2)
      check:
        aggregate.sync_committee_bits.countOnes == 1
        aggregate.sync_committee_signature == sig4.toValidatorSig

    block:
      # Checking for a block that got votes from 2 committees
      let aggregate = pool.produceSyncAggregate(root1)
      let expectedSig = aggregate [sig1, sig2, sig3]
      check:
        aggregate.sync_committee_bits.countOnes == 3
        aggregate.sync_committee_signature == expectedSig.toValidatorSig

    # Pruning the data
    #
    pool.pruneData(Slot(200))

    block:
      # After pruning, all votes are gone
      var outContribution: SyncCommitteeContribution
      let success = pool.produceContribution(
        root1Slot,
        root1,
        subcommittee1,
        outContribution)

      check:
        not success

      let aggregate = pool.produceSyncAggregate(root2)
      check:
        aggregate.sync_committee_bits.isZeros
        aggregate.sync_committee_signature == ValidatorSig.infinity
