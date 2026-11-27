# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[algorithm, options, os],
  unittest2,
  stew/io2,
  ../beacon_chain/spec/[pq_vrf, xmss],
  ../beacon_chain/beacon_clock,
  ../beacon_chain/validators/[pq_key_files, pq_tree_cache, validator_duties],
  ../beacon_chain/validator_client/common,
  ./testblockutil

func forkKeys(
    forks: openArray[(string, string, uint64)]): VCRuntimeConfig =
  ## The `_FORK_VERSION` and `_FORK_EPOCH` values of a `/eth/v1/config/spec`
  ## response.
  var res: VCRuntimeConfig
  res["GENESIS_FORK_VERSION"] = "0x10000038"
  for (name, version, epoch) in forks:
    res[name & "_FORK_VERSION"] = version
    res[name & "_FORK_EPOCH"] = $epoch
  res

const
  fuluForks = [
    ("ALTAIR", "0x20000038", 0'u64), ("BELLATRIX", "0x30000038", 0'u64),
    ("CAPELLA", "0x40000038", 0'u64), ("DENEB", "0x50000038", 0'u64),
    ("ELECTRA", "0x60000038", 0'u64), ("FULU", "0x70000038", 0'u64)]
  pqVersion = Version([byte 0x90, 0, 0, 0x38])
  gloasVersion = Version([byte 0x80, 0, 0, 0x38])

suite "PQ validator client":
  test "Fork configuration of a beacon node that does not know PQ":
    let config = forkKeys(fuluForks).getConsensusForkConfig(OptionalForks)
    check:
      config.isOk
      config.get()[ConsensusFork.Fulu].epoch == Epoch(0)
      config.get()[ConsensusFork.Gloas].epoch == FAR_FUTURE_EPOCH
      config.get()[ConsensusFork.Pq].epoch == FAR_FUTURE_EPOCH
      config.get()[ConsensusFork.Heze].epoch == FAR_FUTURE_EPOCH

  test "Fork configuration with later forks scheduled and PQ not":
    let config = forkKeys(
      @fuluForks & @[("GLOAS", "0x80000038", 5'u64),
                     ("HEZE", "0xa0000038", 9'u64)]
    ).getConsensusForkConfig(OptionalForks)
    check:
      config.isOk
      config.get()[ConsensusFork.Gloas].epoch == Epoch(5)
      config.get()[ConsensusFork.Pq].epoch == FAR_FUTURE_EPOCH
      config.get()[ConsensusFork.Heze].epoch == Epoch(9)

  test "Fork configuration of a PQ network":
    let config = forkKeys(
      @fuluForks & @[("GLOAS", "0x80000038", 0'u64),
                     ("PQ", "0x90000038", 0'u64),
                     ("HEZE", "0xa0000038", uint64(FAR_FUTURE_EPOCH))]
    ).getConsensusForkConfig(OptionalForks)
    check:
      config.isOk
      config.get()[ConsensusFork.Pq].epoch == Epoch(0)
      config.get()[ConsensusFork.Pq].version == pqVersion
      config.get()[ConsensusFork.Heze].epoch == FAR_FUTURE_EPOCH

  test "Fork configuration with PQ before the fork it builds on":
    check:
      forkKeys(
        @fuluForks & @[("GLOAS", "0x80000038", 7'u64),
                       ("PQ", "0x90000038", 3'u64)]
      ).getConsensusForkConfig(OptionalForks).isErr
      # A fork that is not optional has to be configured
      forkKeys(fuluForks).getConsensusForkConfig({ConsensusFork.Heze}).isErr

  test "Consensus fork of a fork version":
    let
      known = forkKeys(
        @fuluForks & @[("GLOAS", "0x80000038", 2'u64),
                       ("PQ", "0x90000038", 4'u64)]
      ).getConsensusForkConfig(OptionalForks).expect("valid")
      unknown = forkKeys(
        @fuluForks & @[("GLOAS", "0x80000038", 2'u64)]
      ).getConsensusForkConfig(OptionalForks).expect("valid")
      pqFork = Fork(
        previous_version: gloasVersion, current_version: pqVersion,
        epoch: Epoch(4))
    check:
      known.getConsensusFork(pqFork) == ConsensusFork.Pq
      known.getConsensusFork(Fork(
        previous_version: gloasVersion, current_version: gloasVersion,
        epoch: Epoch(2))) == ConsensusFork.Gloas
      # A scheduled fork that the configuration does not name is taken for
      # the latest configured fork before it
      unknown.getConsensusFork(pqFork) == ConsensusFork.Gloas
      unknown.getConsensusFork(Fork(
        previous_version: gloasVersion, current_version: pqVersion,
        epoch: Epoch(1))) == ConsensusFork.Fulu

  test "XMSS tree cache source":
    check:
      xmssCacheSource(none(string), none(string)).isNone
      xmssCacheSource(some("/a/keys.xmss"), some("/b/keys.vrf")) ==
        Opt.some((source: "/a/keys.xmss", guessed: false))
      xmssCacheSource(none(string), some("https://host/keys.vrf")) ==
        Opt.some((source: "https://host/keys.xmss", guessed: true))
      # Only a `.vrf` file has a cache file beside it
      xmssCacheSource(none(string), some("https://host/keys.bin")).isNone

  test "Runs of XMSS tree cache records":
    check:
      toRuns(default(seq[uint64])).len == 0
      toRuns([3'u64, 4, 5, 9, 11, 12]) ==
        @[(first: 3'u64, count: 3'u64), (first: 9'u64, count: 1'u64),
          (first: 11'u64, count: 2'u64)]

  test "VRF tree state records of local keys":
    var
      data = newSeq[byte](3 * VRF_TREE_STATE_SIZE + 5)
      secondLeaves: Table[Eth2Digest, ValidatorPubKey]
    let
      seeds = [vrfSeed([byte 1]), vrfSeed([byte 2]), vrfSeed([byte 3])]
      keys = [
        MockPubKeys[ValidatorIndex(0)], MockPubKeys[ValidatorIndex(1)],
        MockPubKeys[ValidatorIndex(2)]]
    # Records of the keys 1, 0 and of a key that is not local; key 2 has none
    for record, seed in [seeds[1], seeds[0], vrfSeed([byte 9])]:
      let at = record * VRF_TREE_STATE_SIZE + 36
      data[at ..< at + 32] = vrfLeaf(seed, 1).data
    for i, seed in seeds:
      secondLeaves[vrfLeaf(seed, 1)] = keys[i]
    let records = findVrfTreeStates(data, secondLeaves)
    check:
      records.len == 2
      records.getOrDefault(keys[0], 99) == 1
      records.getOrDefault(keys[1], 99) == 0
      keys[2] notin records
      findVrfTreeStates(default(seq[byte]), secondLeaves).len == 0

  test "Duties of local validators by XMSS public key":
    var pool = ValidatorPool.init(nil, false)
    let
      validator = pool.addValidator(
        KeystoreData(
          kind: KeystoreKind.Local,
          pubkey: MockPubKeys[ValidatorIndex(0)],
          privateKey: MockPrivKeys[ValidatorIndex(0)]),
        default(Eth1Address), 0'u64)
      other = pool.addValidator(
        KeystoreData(
          kind: KeystoreKind.Local,
          pubkey: MockPubKeys[ValidatorIndex(1)],
          privateKey: MockPrivKeys[ValidatorIndex(1)]),
        default(Eth1Address), 0'u64)
      index = ValidatorIndex(7)

    # Without PQ keys, a validator has no duties in a PQ epoch
    pool.setValidatorIndex(validator, index)
    check pool.toLocalDuty(RestPqProposerDuty(
      validator_index: index, slot: Slot(3))).isNone

    check:
      pool.pqVrfSecondLeaves().len == 2
      pool.pqPublicParams().len == 2
    pool.initPqKeys(default(XmssTreeCaches))
    let
      xmssKey = validator.xmssPubkey.expect("derived")
      otherKey = other.xmssPubkey.expect("derived")
    check:
      xmssKey != otherKey
      xmssKey.publicParam ==
        xmssPublicParam(toSha256Digest(
          @("leanxmss-seed".toOpenArrayByte(0, 12)) &
          @(MockPrivKeys[ValidatorIndex(0)].toRaw()))).expect("param")
      pool.pqVrfSecondLeaves().len == 0

    let attesterDuty = pool.toLocalDuty(RestPqAttesterDuty(
      pubkey: xmssKey, validator_index: index,
      committee_index: CommitteeIndex(2), committee_length: 11,
      committees_at_slot: 4, validator_committee_index: 6, slot: Slot(9),
      is_aggregator: true))
    check:
      attesterDuty == Opt.some(RestAttesterDuty(
        pubkey: validator.pubkey, validator_index: index,
        committee_index: CommitteeIndex(2), committee_length: 11,
        committees_at_slot: 4, validator_committee_index: 6, slot: Slot(9)))
      pool.toLocalDuty(RestPqProposerDuty(
        pubkey: xmssKey, validator_index: index, slot: Slot(3))) ==
        Opt.some(RestProposerDuty(
          pubkey: validator.pubkey, validator_index: index, slot: Slot(3)))
      pool.toLocalDuty(RestPqPtcDuty(
        pubkey: xmssKey, validator_index: index, slot: Slot(4))) ==
        Opt.some(RestPtcDuty(
          pubkey: validator.pubkey, validator_index: index, slot: Slot(4)))
      # The duty of another validator at an index of ours, of a validator
      # whose index is not known yet and of a validator that is not ours
      pool.toLocalDuty(RestPqProposerDuty(
        pubkey: otherKey, validator_index: index, slot: Slot(3))).isNone
      pool.toLocalDuty(RestPqProposerDuty(
        pubkey: otherKey, validator_index: ValidatorIndex(8),
        slot: Slot(3))).isNone
      pool.toLocalDuty(RestPqPtcDuty(
        pubkey: xmssKey, validator_index: ValidatorIndex(1000),
        slot: Slot(3))).isNone

proc testRecord(index: int, bottomTrees: int): PqTreeCacheRecord =
  ## A record with trees of the sizes of real ones; the file does not look
  ## into them.
  var record = PqTreeCacheRecord(
    pubkey: MockPubKeys[ValidatorIndex(index)],
    xmssTrees: newSeq[byte](
      XMSS_CACHED_TOP_TREE_SIZE + bottomTrees * XMSS_CACHED_BOTTOM_TREE_SIZE),
    vrfSubtreeRoots: newSeq[byte](VRF_SUBTREE_ROOTS_SIZE))
  record.xmssPubkey.blob[0] = byte(index + 1)
  for i in 0 ..< record.xmssTrees.len:
    record.xmssTrees[i] = byte((i + index) mod 251)
  for i in 0 ..< bottomTrees:
    # The index of a bottom tree is what it starts with
    record.xmssTrees[
      XMSS_CACHED_TOP_TREE_SIZE + i * XMSS_CACHED_BOTTOM_TREE_SIZE ..<
      XMSS_CACHED_TOP_TREE_SIZE + i * XMSS_CACHED_BOTTOM_TREE_SIZE + 4] =
        [byte(9 - i), 0, 0, 0]
  for i in 0 ..< record.vrfSubtreeRoots.len:
    record.vrfSubtreeRoots[i] = byte((i * 7 + index) mod 253)
  record

proc writeRecords(path: string, records: openArray[PqTreeCacheRecord]) =
  var writer = PqTreeCacheWriter.init(path).expect("writer")
  for record in records:
    writer.add(record).expect("record written")
  writer.finish().expect("file replaced")

proc testPath(): string =
  getTempDir() / "nimbus_pq_tree_cache_test_" & $getCurrentProcessId() & ".bin"

suite "PQ attestation timing":
  # The clock is the wall clock: a genesis whole seconds ago puts now in the
  # first second of a slot, or in its sixth
  let timeParams = defaultRuntimeConfig.timeParams
  doAssert timeParams.SLOT_DURATION.seconds == 12

  proc clockAt(secondOfSlot: uint64): BeaconClock =
    BeaconClock.init(
      timeParams, uint64(getTime().toUnix()) - 10 * 12 - secondOfSlot).get()

  test "Attestations to a block are held back for a sixth of the deadline":
    let
      clock = clockAt(0)
      delay = clock.afterBlockDelay(clock.currentSlot(), ConsensusFork.Pq)
    check:
      timeParams.attestationSlotOffsetGloas.nanoseconds == 3_000_000_000
      delay <= chronos.milliseconds(500)
      delay > chronos.milliseconds(250)

  test "Attestations to a block before PQ are held back as they were":
    let
      clock = clockAt(0)
      delay = clock.afterBlockDelay(clock.currentSlot(), ConsensusFork.Fulu)
    check:
      delay <= chronos.milliseconds(2000)
      delay > chronos.milliseconds(1750)

  test "Attestations to a block after the deadline are not held back":
    let clock = clockAt(5)
    check:
      clock.afterBlockDelay(clock.currentSlot(), ConsensusFork.Pq) ==
        ZeroDuration

suite "PQ tree cache":
  setup:
    let path = testPath()

  teardown:
    discard tryRemoveFile(path)
    discard tryRemoveFile(path & ".tmp")

  test "Records are read back":
    var noVrf = testRecord(2, 0)
    noVrf.vrfSubtreeRoots.setLen(0)
    let records = [testRecord(0, 2), testRecord(1, 4), noVrf]
    writeRecords(path, records)
    check:
      readPqTreeCache(path) == @records
      xmssBottomTrees(records[1].xmssTrees) == @[9'u32, 8, 7, 6]
      xmssBottomTrees(records[2].xmssTrees).len == 0
      not fileExists(path & ".tmp")
      readPqTreeCache(path & ".absent").len == 0

  test "Trees of unexpected sizes are not written":
    var
      writer = PqTreeCacheWriter.init(path).expect("writer")
      record = testRecord(0, 1)
    record.xmssTrees.setLen(record.xmssTrees.len - 1)
    check writer.add(record).isErr
    record = testRecord(0, XMSS_MAX_CACHED_BOTTOM_TREES + 1)
    check writer.add(record).isErr
    record = testRecord(0, 1)
    record.vrfSubtreeRoots.setLen(32)
    check writer.add(record).isErr
    writer.abandon()
    check:
      not fileExists(path)
      not fileExists(path & ".tmp")

  test "A damaged record ends the reading":
    let records = [testRecord(0, 1), testRecord(1, 1), testRecord(2, 1)]
    writeRecords(path, records)
    let data = io2.readAllBytes(path).expect("file")

    # In the trees of the second record
    var damaged = data
    damaged[data.len div 2] = damaged[data.len div 2] xor 1
    check io2.writeFile(path, damaged).isOk
    check readPqTreeCache(path) == @[records[0]]

    # Cut short within the third record
    check io2.writeFile(path, data.toOpenArray(0, data.len - 10)).isOk
    check readPqTreeCache(path) == @[records[0], records[1]]

    # Not such a file
    damaged = data
    damaged[0] = damaged[0] xor 1
    check io2.writeFile(path, damaged).isOk
    check readPqTreeCache(path).len == 0

  test "A file that is not finished leaves the previous one":
    let records = [testRecord(0, 1)]
    writeRecords(path, records)
    var writer = PqTreeCacheWriter.init(path).expect("writer")
    writer.add(testRecord(1, 2)).expect("record written")
    writer.abandon()
    check:
      readPqTreeCache(path) == @records
      not fileExists(path & ".tmp")

  test "Trees of local validators are kept across restarts":
    proc newPool(): ValidatorPool =
      var pool = ValidatorPool.init(nil, false)
      for i in 0 ..< 2:
        discard pool.addValidator(
          KeystoreData(
            kind: KeystoreKind.Local,
            pubkey: MockPubKeys[ValidatorIndex(i)],
            privateKey: MockPrivKeys[ValidatorIndex(i)]),
          default(Eth1Address), 0'u64)
      pool.pqTreeCachePath = path
      pool

    proc bottomTrees(pool: ValidatorPool, index: int): seq[uint32] =
      let validator = pool.getValidator(
        MockPubKeys[ValidatorIndex(index)]).expect("validator")
      sorted(xmssBottomTrees(validator.pqKeys.xmss.treeCache()))

    const
      slotLeaf = 3'u64 shl XMSS_LAYER_HEIGHT
      laterLeaf = 4'u64 shl XMSS_LAYER_HEIGHT

    # The first run hashes the trees and writes them
    var first = newPool()
    check first.loadPqTreeCache().len == 0
    first.initPqKeys(default(XmssTreeCaches))
    first.preparePqLeaves([slotLeaf, slotLeaf + 5])
    check:
      first.bottomTrees(0) == @[3'u32]
      not fileExists(path)
    first.savePqTreeCache()
    check readPqTreeCache(path).len == 2

    # The next one loads them: no tree is hashed
    var second = newPool()
    let caches = second.loadPqTreeCache()
    check caches.len == 2
    for cache in caches.values:
      check cache.vrfSubtreeRoots.len == VRF_SUBTREE_ROOTS_SIZE
    second.initPqKeys(caches)
    for i in 0 ..< 2:
      let
        pubkey = MockPubKeys[ValidatorIndex(i)]
        loaded = second.getValidator(pubkey).expect("validator")
        hashed = first.getValidator(pubkey).expect("validator")
      check:
        loaded.xmssPubkey == hashed.xmssPubkey
        loaded.xmssPubkey.isSome
        second.bottomTrees(i) == @[3'u32]
        loaded.pqKeys.vrf.subtreeRoots == hashed.pqKeys.vrf.subtreeRoots
    # Validators with PQ keys are not loaded again
    check second.loadPqTreeCache().len == 0

    # The file is written again only when the trees have changed
    check tryRemoveFile(path)
    second.savePqTreeCache()
    check not fileExists(path)
    second.preparePqLeaves([laterLeaf])
    second.savePqTreeCache()
    let records = readPqTreeCache(path)
    check records.len == 2
    for record in records:
      check sorted(xmssBottomTrees(record.xmssTrees)) == @[3'u32, 4]

    # A file of other keys is not used: the trees are hashed
    var others = [testRecord(0, 1), testRecord(1, 1)]
    writeRecords(path, others)
    var third = newPool()
    third.initPqKeys(third.loadPqTreeCache())
    check:
      third.getValidator(MockPubKeys[ValidatorIndex(0)]).expect(
        "validator").xmssPubkey ==
          first.getValidator(MockPubKeys[ValidatorIndex(0)]).expect(
            "validator").xmssPubkey
      third.bottomTrees(0).len == 0
