# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Status lib
  unittest2,
  chronos,
  taskpools,
  blscurve/blst/blst_abi,
  # Internal
  ../beacon_chain/gossip_processing/batch_validation,
  ../beacon_chain/consensus_object_pools/[
    block_clearance, blockchain_dag, spec_cache],
  ../beacon_chain/spec/[beaconstate, signatures_batch, state_transition, validator],
  ../beacon_chain/validators/validator_monitor,
  # Test utilities
  ./testutil, ./testdbutil, ./testblockutil, ./consensus_spec/fixtures_utils

from std/sequtils import anyIt, countIt, mapIt, repeat
from ./testbcutil import addHeadBlock

const
  committees_per_slot = 3'u64
  active_validators =
    committees_per_slot * TARGET_COMMITTEE_SIZE * SLOTS_PER_EPOCH
  committee_count = committees_per_slot * SLOTS_PER_EPOCH
  testSlot = Slot(SLOTS_PER_EPOCH * 2 + 1)

func negated(key: CookedPubKey): CookedPubKey =
  ## Point with the same x and the opposite y
  result = key
  let y = cast[ptr cblst_fp](cast[uint](addr result) + 48'u)
  blst_fp_cneg(y, y, true)

func addedUp(keys: openArray[CookedPubKey]): CookedPubKey =
  var agg {.noinit.}: AggregatePublicKey
  agg.init(keys[0])
  for i in 1 ..< keys.len:
    agg.aggregate(keys[i])
  finish(agg)

func isSameKey(a, b: CookedPubKey): bool =
  a.toPubKey() == b.toPubKey()

proc testValidators(): seq[ImmutableValidatorData2] =
  for i in 0'u64 ..< active_validators:
    result.add ImmutableValidatorData2(
      pubkey: MockPrivKeys[ValidatorIndex(i)].toPubKey())

proc testShuffling(): seq[ValidatorIndex] =
  for i in countdown(active_validators.int - 1, 0):
    result.add ValidatorIndex(i)

let
  validatorKeys = testValidators()
  shuffled = testShuffling()

proc committeeMembers(committee_index: uint64): seq[ValidatorIndex] =
  let index = (testSlot mod SLOTS_PER_EPOCH) * committees_per_slot + committee_index
  shuffled[compute_committee_slice(active_validators, index, committee_count)]

proc committeeBits(committees: openArray[uint64]): AttestationCommitteeBits =
  for committee_index in committees:
    result[committee_index.int] = true

proc participants(
    committees: openArray[uint64],
    missed: openArray[int]): seq[ValidatorIndex] =
  var position = 0
  for committee_index in committees:
    for validator_index in committeeMembers(committee_index):
      if position notin missed:
        result.add validator_index
      position += 1

proc aggregationBits(
    T: type, committees: openArray[uint64], missed: openArray[int]): T =
  var numMembers = 0
  for committee_index in committees:
    numMembers += committeeMembers(committee_index).len
  result = T.init(numMembers)
  for position in 0 ..< numMembers:
    if position notin missed:
      result.setBit(position)

proc expectedKey(
    committees: openArray[uint64], missed: openArray[int]): CookedPubKey =
  addedUp(participants(committees, missed).mapIt(validatorKeys[it.int].pubkey))

suite "Committee aggregates" & preset():
  setup:
    let aggregates = CommitteeAggregates(epoch: testSlot.epoch)

  test "Subtracting non-participants matches adding up the attesters":
    for (committees, missed) in [
        (@[0'u64], @[1]),
        (@[1'u64], newSeq[int]()),
        (@[0'u64, 2'u64], @[0, 5]),
        (@[0'u64, 1'u64, 2'u64], newSeq[int]()),
        (@[0'u64, 1'u64, 2'u64], @[int(3 * TARGET_COMMITTEE_SIZE - 1)])]:
      let
        electraKey = aggregates.subtractNonParticipants(
          shuffled, testSlot, committeeBits(committees),
          electra.AggregationBits.aggregationBits(committees, missed),
          validatorKeys)
        gloasKey = aggregates.subtractNonParticipants(
          shuffled, testSlot, committeeBits(committees),
          gloas.AggregationBits.aggregationBits(committees, missed),
          validatorKeys)
      check:
        electraKey.isSome()
        electraKey.get().isSameKey(expectedKey(committees, missed))
        gloasKey.isSome()
        gloasKey.get().isSameKey(expectedKey(committees, missed))

  test "Committee sums are computed once, for the committees in use":
    let
      index = (testSlot mod SLOTS_PER_EPOCH).int * committees_per_slot.int + 1
      bits = electra.AggregationBits.aggregationBits([1'u64], [0])

    check:
      aggregates.subtractNonParticipants(
        shuffled, testSlot, committeeBits([1'u64]), bits, validatorKeys).isSome()
      aggregates.keys.lenu64 == committee_count
      aggregates.keys.countIt(it.isSome()) == 1
      aggregates.keys[index].get().isSameKey(expectedKey([1'u64], []))

    aggregates.keys[index] = Opt.some(validatorKeys[0].pubkey)
    check not aggregates.subtractNonParticipants(
      shuffled, testSlot, committeeBits([1'u64]), bits, validatorKeys
    ).get().isSameKey(expectedKey([1'u64], [0]))

  test "Attesters are added up when that's cheaper":
    let half = int(TARGET_COMMITTEE_SIZE div 2)
    var mostMissed, allMissed: seq[int]
    for position in 0 ..< TARGET_COMMITTEE_SIZE.int:
      allMissed.add position
      if position >= half:
        mostMissed.add position

    check:
      aggregates.subtractNonParticipants(
        shuffled, testSlot, committeeBits([0'u64]),
        electra.AggregationBits.aggregationBits([0'u64], mostMissed),
        validatorKeys).isNone()
      aggregates.subtractNonParticipants(
        shuffled, testSlot, committeeBits([0'u64]),
        electra.AggregationBits.aggregationBits([0'u64], allMissed),
        validatorKeys).isNone()
      aggregates.keys.countIt(it.isSome()) == 0

  test "Attestations that don't match the shuffling are left alone":
    let
      numMembers = committeeMembers(0).len
      cBits = committeeBits([0'u64])
      aBits = electra.AggregationBits.aggregationBits([0'u64], [])
      wrongLength = committee_count.int + 1
      otherEpoch = CommitteeAggregates(epoch: testSlot.epoch + 1)
      otherCount = CommitteeAggregates(
        epoch: testSlot.epoch,
        keys: newSeq[Opt[CookedPubKey]](wrongLength))
      noMembers = CommitteeAggregates(epoch: testSlot.epoch)
    var
      tooShort = electra.AggregationBits.init(numMembers - 1)
      tooLong = electra.AggregationBits.init(numMembers + 1)
      outOfRange: AttestationCommitteeBits
    for i in 0 ..< numMembers - 1:
      tooShort.setBit(i)
    for i in 0 ..< numMembers + 1:
      tooLong.setBit(i)
    outOfRange[committees_per_slot.int] = true

    check:
      # Sanity check that it's the deviation that makes these fail
      aggregates.subtractNonParticipants(
        shuffled, testSlot, cBits, aBits, validatorKeys).isSome()

      aggregates.subtractNonParticipants(
        shuffled, testSlot, cBits, tooShort, validatorKeys).isNone()
      aggregates.subtractNonParticipants(
        shuffled, testSlot, cBits, tooLong, validatorKeys).isNone()
      aggregates.subtractNonParticipants(
        shuffled, testSlot, default(AttestationCommitteeBits), aBits,
        validatorKeys).isNone()
      aggregates.subtractNonParticipants(
        shuffled, testSlot, outOfRange, aBits, validatorKeys).isNone()
      aggregates.subtractNonParticipants(
        shuffled, testSlot + SLOTS_PER_EPOCH, cBits, aBits,
        validatorKeys).isNone()
      CommitteeAggregates(nil).subtractNonParticipants(
        shuffled, testSlot, cBits, aBits, validatorKeys).isNone()
      otherEpoch.subtractNonParticipants(
        shuffled, testSlot, cBits, aBits, validatorKeys).isNone()
      otherCount.subtractNonParticipants(
        shuffled, testSlot, cBits, aBits, validatorKeys).isNone()

      # A committee without members has nothing to start from
      noMembers.subtractNonParticipants(
        shuffled.toOpenArray(0, 2), testSlot, cBits,
        electra.AggregationBits.init(0), validatorKeys).isNone()

      # The validators don't need to be known either, as this isn't verified yet
      CommitteeAggregates(epoch: testSlot.epoch).subtractNonParticipants(
        shuffled, testSlot, cBits, aBits,
        validatorKeys.toOpenArray(0, 0)).isNone()

  test "Keys that cancel out or repeat":
    let
      P = validatorKeys[0].pubkey
      Q = validatorKeys[1].pubkey
      minusP = negated(P)

    check:
      # Attesters cancel out, leaving the point at infinity
      addedUp([P, minusP, Q]).subtractAll([Q]).isSameKey(addedUp([P, minusP]))
      # The full aggregate is the point at infinity
      addedUp([P, minusP]).subtractAll([minusP]).isSameKey(P)
      # Non-participants cancel out
      addedUp([P, minusP, Q]).subtractAll([P, minusP]).isSameKey(Q)
      # A seat is removed, not the validator - sync committees repeat validators
      addedUp([P, P, Q]).subtractAll([P]).isSameKey(addedUp([P, Q]))
      addedUp([P, P, Q]).subtractAll([]).isSameKey(addedUp([P, P, Q]))

    # Same thing for an entire committee summing up to the point at infinity
    var keys = validatorKeys
    let members = committeeMembers(0)
    for i in countup(0, members.len - 2, 2):
      keys[members[i + 1].int].pubkey = negated(keys[members[i].int].pubkey)

    let key = aggregates.subtractNonParticipants(
      shuffled, testSlot, committeeBits([0'u64]),
      electra.AggregationBits.aggregationBits([0'u64], []), keys)
    check:
      key.isSome()
      key.get().isSameKey(addedUp(members.mapIt(keys[it.int].pubkey)))

suite "Committee aggregates in the DAG" & preset():
  setup:
    let
      rng = HmacDrbgContext.new()
      cfg = genesisTestRuntimeConfig(ConsensusFork.Electra)
      validatorMonitor = newClone(ValidatorMonitor.init(cfg))
      dag = init(
        ChainDAGRef, cfg,
        cfg.makeTestDB(2 * TARGET_COMMITTEE_SIZE * SLOTS_PER_EPOCH),
        validatorMonitor, {})
      state = newClone(dag.headState)
    var
      taskpool = Taskpool.new()
      verifier = BatchVerifier.init(rng, taskpool)
      cache: StateCache
      info: ForkedEpochInfo

    proc addBlock(blck: ForkedSignedBeaconBlock): BlockRef =
      dag.addHeadBlock(
        verifier, blck.electraData, OnBlockAdded[ConsensusFork.Electra](nil)
      ).expect("signatures to verify against the committee sums")

  teardown:
    taskpool.shutdown()

  test "Blocks verify against the sums":
    # 3/4 of the sync committee makes this take the subtraction path as well
    var head: BlockRef
    for blck in makeTestBlocks(
        dag.headState, cache, int(SLOTS_PER_EPOCH + 2), attested = true,
        syncCommitteeRatio = 0.75, cfg = dag.cfg):
      head = addBlock(blck)

    # Without this, all of the above is just the regular code path
    for epoch in [head.slot.epoch - 1, head.slot.epoch]:
      check dag.findShufflingRef(head.bid, epoch).get()
        .committee_aggregates.keys.anyIt(it.isSome())

  test "Sums only apply to the shuffling they belong to":
    check process_slots(
      dag.cfg, state[], Slot(SLOTS_PER_EPOCH + 3), cache, info, {}).isOk()
    let
      epoch = state[].slot.epoch
      parent_root = withState(state[]): forkyState.latest_block_root
      attestations = makeFullElectraAttestations(
        state[], parent_root, state[].slot, cache)
      preState = newClone(state[])
      blck = addTestBlock(
        state[], cache, electraAttestations = attestations, cfg = dag.cfg)
    check process_slots(
      dag.cfg, preState[], blck.slot, cache, info, {}).isOk()

    let
      shuffling_root = withState(preState[]):
        forkyState.dependent_root(epoch.get_previous_epoch)
      wrong = Opt.some(validatorKeys[0].pubkey)
      wrongKeys = repeat(
        wrong,
        int(get_committee_count_per_slot(preState[], epoch, cache) * SLOTS_PER_EPOCH))

    proc signatureSets(cache: var StateCache): seq[string] =
      var sigs: seq[SignatureSet]
      check sigs.collectSignatureSets(
        blck.electraData, dag.db.immutableValidators, preState[],
        dag.cfg.GENESIS_FORK_VERSION, dag.cfg.CAPELLA_FORK_VERSION, cache
      ).isOk()
      sigs.mapIt($it)

    var plainCache: StateCache
    discard get_shuffled_active_validator_indices(plainCache, preState[], epoch)
    let expected = signatureSets(plainCache)

    var
      otherForkCache = plainCache
      wrongSumsCache = plainCache
      emptyCache = plainCache
      otherFork = CommitteeAggregates(
        epoch: epoch, attester_dependent_root: ZERO_HASH, keys: wrongKeys)
      wrongSums = CommitteeAggregates(
        epoch: epoch, attester_dependent_root: shuffling_root, keys: wrongKeys)
      empty = CommitteeAggregates(
        epoch: epoch, attester_dependent_root: shuffling_root)
    otherForkCache.committee_aggregates[epoch] = otherFork
    wrongSumsCache.committee_aggregates[epoch] = wrongSums
    emptyCache.committee_aggregates[epoch] = empty

    check:
      signatureSets(otherForkCache) == expected
      # Ensures that the above didn't pass for an unrelated reason
      signatureSets(wrongSumsCache) != expected
      signatureSets(emptyCache) == expected
      empty.keys.anyIt(it.isSome())

  test "Each fork gets its own sums":
    # Create two alternate histories with different shufflings
    check process_slots(
      dag.cfg, state[], (SLOTS_PER_EPOCH - 2).Slot, cache, info, {}).isOk()
    let state2 = newClone(state[])

    const epoch = 3.Epoch
    proc fillToEpoch(
        state: ref ForkedHashedBeaconState, cache: var StateCache): BlockRef =
      while state[].slot.epoch <= epoch:
        check process_slots(
          dag.cfg, state[], state[].slot + 1, cache, info, {}).isOk()
        let
          parent_root = withState(state[]): forkyState.latest_block_root
          attestations = makeFullElectraAttestations(
            state[], parent_root, state[].slot, cache)
        result = addBlock(addTestBlock(
          state[], cache, electraAttestations = attestations, cfg = dag.cfg))

    # History 1 contains all odd blocks, history 2 contains all even blocks
    let head1 = state.fillToEpoch(cache)
    var cache2: StateCache
    check process_slots(
      dag.cfg, state2[], state2[].slot + 1, cache2, info, {}).isOk()
    let
      head2 = state2.fillToEpoch(cache2)
      aggregates1 = dag.findShufflingRef(head1.bid, epoch).get().committee_aggregates
      aggregates2 = dag.findShufflingRef(head2.bid, epoch).get().committee_aggregates

    check:
      aggregates1.attester_dependent_root != aggregates2.attester_dependent_root
      aggregates1.keys.anyIt(it.isSome())
      aggregates2.keys.anyIt(it.isSome())

  test "Gossip aggregates verify against the sums":
    let
      rng2 = HmacDrbgContext.new()
      batchCrypto = BatchCrypto.new(
        rng2, cfg.timeParams, eager = proc(): bool = false,
        genesis_validators_root = dag.genesis_validators_root, taskpool
      ).expect("working batcher")
      slot = dag.head.slot + 1
      shufflingRef = dag.getShufflingRef(dag.head, slot.epoch, false).get()
    check process_slots(dag.cfg, state[], slot, cache, info, {}).isOk()

    let
      attestation = makeFullElectraAttestations(
        state[], dag.head.root, slot, cache)[0]
      sig = attestation.signature.load().get()
      attesting_indices = shufflingRef.get_attesting_indices(
        slot, attestation.committee_bits, attestation.aggregation_bits)
      aggregate = electra.SignedAggregateAndProof(
        message: electra.AggregateAndProof(
          aggregator_index: attesting_indices[0].uint64,
          aggregate: attestation,
          selection_proof: attestation.signature),
        signature: attestation.signature)
      fork = dag.forkAtEpoch(slot.epoch)

    proc aggregateResult(): BatchResult =
      try:
        waitFor(batchCrypto.scheduleAggregateChecks(
          fork, aggregate, sig, dag, shufflingRef, attesting_indices
        ).expect("signatures to load").aggregateFut)
      except CatchableError:
        BatchResult.Timeout

    check:
      aggregateResult() == BatchResult.Valid
      shufflingRef.committee_aggregates.keys.countIt(it.isSome()) == 1

    # Ensures that it's the cached sum that got verified
    for key in shufflingRef.committee_aggregates.keys.mitems():
      if key.isSome():
        key = Opt.some(validatorKeys[0].pubkey)
    check aggregateResult() == BatchResult.Invalid
