# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/options,
  unittest2,
  ../beacon_chain/spec/[pq_vrf, xmss],
  ../beacon_chain/validators/pq_key_files,
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
      data[at ..< at + 32] = compute_vrf_leaf(seed, 1).data
    for i, seed in seeds:
      secondLeaves[compute_vrf_leaf(seed, 1)] = keys[i]
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
