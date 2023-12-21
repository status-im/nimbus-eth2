# beacon_chain
# Copyright (c) 2020-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2,
  ./testutil,
  ../beacon_chain/spec/[network, validator]

from std/sequtils import toSeq

suite "Honest validator":
  var forkDigest: ForkDigest

  test "General pubsub topics":
    check:
      getBeaconBlocksTopic(forkDigest) == "/eth2/00000000/beacon_block/ssz_snappy"
      getVoluntaryExitsTopic(forkDigest) == "/eth2/00000000/voluntary_exit/ssz_snappy"
      getProposerSlashingsTopic(forkDigest) == "/eth2/00000000/proposer_slashing/ssz_snappy"
      getAttesterSlashingsTopic(forkDigest) == "/eth2/00000000/attester_slashing/ssz_snappy"
      getAggregateAndProofsTopic(forkDigest) == "/eth2/00000000/beacon_aggregate_and_proof/ssz_snappy"
      getBlsToExecutionChangeTopic(forkDigest) == "/eth2/00000000/bls_to_execution_change/ssz_snappy"
      getSyncCommitteeContributionAndProofTopic(forkDigest) == "/eth2/00000000/sync_committee_contribution_and_proof/ssz_snappy"
      getLightClientFinalityUpdateTopic(forkDigest) == "/eth2/00000000/light_client_finality_update/ssz_snappy"
      getLightClientOptimisticUpdateTopic(forkDigest) == "/eth2/00000000/light_client_optimistic_update/ssz_snappy"

  test "Mainnet attestation topics":
    check:
      getAttestationTopic(forkDigest, SubnetId(0)) ==
        "/eth2/00000000/beacon_attestation_0/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(5)) ==
        "/eth2/00000000/beacon_attestation_5/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(7)) ==
        "/eth2/00000000/beacon_attestation_7/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(9)) ==
        "/eth2/00000000/beacon_attestation_9/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(13)) ==
        "/eth2/00000000/beacon_attestation_13/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(19)) ==
        "/eth2/00000000/beacon_attestation_19/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(20)) ==
        "/eth2/00000000/beacon_attestation_20/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(22)) ==
        "/eth2/00000000/beacon_attestation_22/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(25)) ==
        "/eth2/00000000/beacon_attestation_25/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(27)) ==
        "/eth2/00000000/beacon_attestation_27/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(31)) ==
        "/eth2/00000000/beacon_attestation_31/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(39)) ==
        "/eth2/00000000/beacon_attestation_39/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(45)) ==
        "/eth2/00000000/beacon_attestation_45/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(47)) ==
        "/eth2/00000000/beacon_attestation_47/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(48)) ==
        "/eth2/00000000/beacon_attestation_48/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(50)) ==
        "/eth2/00000000/beacon_attestation_50/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(53)) ==
        "/eth2/00000000/beacon_attestation_53/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(54)) ==
        "/eth2/00000000/beacon_attestation_54/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(62)) ==
        "/eth2/00000000/beacon_attestation_62/ssz_snappy"
      getAttestationTopic(forkDigest, SubnetId(63)) ==
        "/eth2/00000000/beacon_attestation_63/ssz_snappy"
      getSyncCommitteeTopic(forkDigest, SyncSubcommitteeIndex(0)) ==
        "/eth2/00000000/sync_committee_0/ssz_snappy"
      getSyncCommitteeTopic(forkDigest, SyncSubcommitteeIndex(1)) ==
        "/eth2/00000000/sync_committee_1/ssz_snappy"
      getSyncCommitteeTopic(forkDigest, SyncSubcommitteeIndex(3)) ==
        "/eth2/00000000/sync_committee_3/ssz_snappy"
      getBlobSidecarTopic(forkDigest, BlobId(1)) ==
        "/eth2/00000000/blob_sidecar_1/ssz_snappy"
      toSeq(blobSidecarTopics(forkDigest)) ==
        ["/eth2/00000000/blob_sidecar_0/ssz_snappy",
         "/eth2/00000000/blob_sidecar_1/ssz_snappy",
         "/eth2/00000000/blob_sidecar_2/ssz_snappy",
         "/eth2/00000000/blob_sidecar_3/ssz_snappy",
         "/eth2/00000000/blob_sidecar_4/ssz_snappy",
         "/eth2/00000000/blob_sidecar_5/ssz_snappy"]

  test "is_aggregator":
    check:
      not is_aggregator(146, ValidatorSig.fromHex(
        "aa176502f0a5e954e4c6b452d0e11a03513c19b6d189f125f07b6c5c120df011c31da4c4a9c4a52a5a48fcba5b14d7b316b986a146187966d2341388bbf1f86c42e90553ba009ba10edc6b5544a6e945ce6d2419197f66ab2b9df2b0a0c89987")[])

      is_aggregator(147, ValidatorSig.fromHex(
        "91a49ae4edfb4b1c9f7856f49c9b0f6d2278b0f714edd6654bf91678d08c0554b8c8bc375f88ffc227f679bf14287dd616e6d1df264599e56516a3f6ab4d91365cc6a40a7e72edeff37c456d4b2b80fa76283911471fe1e292bf64f54cafd55f")[])

      # https://beaconcha.in/block/62082
      not is_aggregator(150, ValidatorSig.fromHex(
        "97e7192cc0f5ec62dc6ea8b86d822b2020ea80c188a09088104781865375a5b4afb1de08ebd9e877458ae30c30f16844071633f1e3431f1fe6fb298bfd6f5947a229590c9bafca0dfcd111b4ceca135f4298e57ac9b6bd2ba96cfe97675910d8")[])

      # https://beaconcha.in/block/62052
      not is_aggregator(149, ValidatorSig.fromHex(
        "ad5c4e7354393125af9225c86035ebd8834d17ba4f9e895006b52117de452832b360eb5265aaec0ddd4ed41fd3a98a080b22de99cdf056c46f0df256449682f0e521c5010ff049044732848eac2f8d0b5cde94763c72b00d2a2361d71df18038")[])

      # https://beaconcha.in/block/61804
      not is_aggregator(148, ValidatorSig.fromHex(
        "0x8a0b276e0a5c9f7580a015b201e190381be48fad0ae1b228f6132028252463f2079137bfe65a64f5a78eef60c94390b10815d96564acd024d1ae78ea6b167651428ebea83f03337862f36503db55346a14e7e7b8f2ea17ba3651a8c0d1176f68")[])

      # https://beaconcha.in/block/61804
      not is_aggregator(148, ValidatorSig.fromHex(
        "0xaddda60eeba491f06454fb424128f127146e17dd5034051830e7198205bf43dcae481417fa437dbf3a822334c7f2e94902c356c417c23a01e2fa7c3e3bbffcad35e743687b7baf76147a2006ea43a348ad690b90cfb242ddffdf1f7f6c0e26f4")[])

      # https://beaconcha.in/block/61804
      not is_aggregator(148, ValidatorSig.fromHex(
        "0x918878d08ece660c6e9ce2d0f752bb2de016ff99dc7f67a29f672e00656654993a29450ed3a6c47b376a09429b75103d0a8c9fa40eb1c0c0d65eb1bf6635d3a83a6cc644987213ab375b0cb5d25d6f9b89871403dd420a93301c91813bf811d4")[])

      # https://beaconcha.in/block/61804
      not is_aggregator(148, ValidatorSig.fromHex(
        "0xabe02078312c72f0e0ccbae6bf0c90cf509bbfde36e8c04da102882fe80aaf7615237b8bc837cdc9b6a640e53dc1881c0e5905dd3d15052c9cbf7d7fdb02252b6a4e085a6dde593d9217c52324edfbde7999f06c862f4973eca47f05062f50ed")[])

      # https://beaconcha.in/block/61804
      not is_aggregator(148, ValidatorSig.fromHex(
        "0xac08ca70066c6ea0525aa54dd867f82b86945818cb9305aae30f3bee13275dcf13d6d0680a47e889482ff2bb9a9f3cdb0588746f9e30c04645eda6d01bbd0ce6326ceb695294cb338ebace5b130c5b8f2e4f8efa63d63d5bb255c21a39da9c12")[])

      # https://beaconcha.in/block/61757
      not is_aggregator(148, ValidatorSig.fromHex(
        "0xac08ca70066c6ea0525aa54dd867f82b86945818cb9305aae30f3bee13275dcf13d6d0680a47e889482ff2bb9a9f3cdb0588746f9e30c04645eda6d01bbd0ce6326ceb695294cb338ebace5b130c5b8f2e4f8efa63d63d5bb255c21a39da9c12")[])

      # Extracted from Pyrmont and verified against Python executable spec
      not is_aggregator(132, ValidatorSig.fromHex(
        "0x9432e0532f2a265562e2f8be162c2eaa4156c9ff778a59e562188f82757e9292e6b7f84de75aa4eb4e87a1a8aaebde220befda18abb637157db8a8aaf085c4e5a63b4a506f80e88558396bb66c85492ca70ff9d3d357157857f4584f30cb7b5c")[])

      not is_aggregator(133, ValidatorSig.fromHex(
        "0x89d97295f2cee5cc556b316e142529832589a824537cb13f3d6f2145a23b6bf2981beed5715d8b8781310c48b280c1330e9f52feb4d22ac595aefbbe218b0e40c72ff2f4d75293c5355d4c57768384c248a8dbff20b9f4f7453b7d32747690c1")[])

      not is_aggregator(132, ValidatorSig.fromHex(
        "0xafbec4bf82c7c1738259e99aa62568381886928dc4c77653748e6c6a4c46abc18789caee44e29cf55b01d9d29cb3ecb503636c261b9e58b2b36d80fc21668c8d7e2483b78387a5f63e11a1c69e795a73975eedc10ac876af4e5c4c280331d4a1")[])

      not is_aggregator(132, ValidatorSig.fromHex(
        "0xb2724ec19b9c8477549a47fdd7082e539842c005b891788cd373d27fcd8d6b7317d9f9d197591d8fce3671c6e299b5e0145af4b2c6f54e966cd82bbd212ed7d7c1fa8911bbf1f5e9521733e8db1a931cbe76d2a34a1dec6720069027f0d4a10d")[])

      not is_aggregator(132, ValidatorSig.fromHex(
        "0x878051cc81ef7070b365de3fbdb0a70f4feae610294417fc94cf4ab07e95952f798fd870f6dbc2721129bb1f5c3528f41320c8d07a513a90f3b5442a11927b16b979649c90fcb1f407b12ea28b4d9b4177e99a52aab828bf40e5e4908fc56c86")[])

      not is_aggregator(132, ValidatorSig.fromHex(
        "0x8cf2996bee5c5031a019adc75bba3590799ec092dafc6a59b1e8807820ea785721f27ce717ea0f9e922c48a9e2ec27250d08eb847de446f109fd16325dd93eec43836e7ac1cb23b3dc4a73a711522c818c52e45cefafbda0cc686718f6b27c10")[])

      not is_aggregator(133, ValidatorSig.fromHex(
        "0x951b33198b2675561fad24a0cd45be054b59bc99070e804f273ecd0bd3c29a8d8d5369f2f458756a02103da59cf9fab508d0ba447be2fa333b957164e40768be3158be7924bb5059cabcccf428bd2e23d94ce9d32438338fdb5fb64bebcfd433")[])

      not is_aggregator(132, ValidatorSig.fromHex(
        "0x853faf78a64e34e90f086c69f5d6cf147c67e4d06434b8da2758922a3b5af578aafc9d5d0ddb292ea9a4f370cff060ca0769a7b569f1a8df0fafea0ce181310aae6063aa96e020ec1021bd02adcc7e66f623aa25f696b2fb30d31ec0f750c6a1")[])

      not is_aggregator(132, ValidatorSig.fromHex(
        "0xb28489f1e9923ce9ff9a86e8c0cbb26f3631130fc754d8ee978b73b7f07e4474b318c6f3590775b6beffb84f7c90dd3b073a4286238b28766d2274f9a781d01d35ceb42cfe92c8b983476226725a03f5e768ceb5fd265f2c91d2dd281e86f5e7")[])

      not is_aggregator(133, ValidatorSig.fromHex(
        "0xa9cf52565c529a84f98ab2ba244e79bb9f4f5366746fa9bd6e0e92b9e02743c1c63bb7deec70720fc0c6f21f1e5bea79113d75326e236259a890e1847c52230c1e68303f261246f7dcf273e21480fc1162e3a269a839dd468457be5215855d40")[])

      not is_aggregator(132, ValidatorSig.fromHex(
        "0xa2874f85c057f727e4dbcd3df609bc82f754d6adf21dfe66cc46b1f677bf342f71c4b467ffec8376df2ec06e104540b2053f68c0903dddb4b89348c6737f1aec815dc83243c163c6dd53c016f4d2820cc3402438b24b74736de294b5b71e8cba")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0xa564ea93c3476fdc454c43e0b56e046896608adf0a9d2ced9d39a4742d214f6779e46ebb815405cb7a675befed4cc08214d8f17a85a7fec089cdfe95c04707eb7b57045f3a3b65cd80d993e626806c8a69df92894c21e6a1241fdfc18ff2c64f")[])

      is_aggregator(133, ValidatorSig.fromHex(
        "0xa6e6a4a8f2beb878ba06ba58382497ca3c495c7d21579920ca9735f64d560edba9b84e3e379de3dc4c8529ae7209a344109ef5f2411dde16035b079860223c96f8830a2c394b966d2241e691dd3e6a941dcad261e10f2ed08e43fea59cadc26f")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0x87a645d5eab8c687724f52f9aeefd4a639d70a4621e9254f698ce071a88650e10d7a17b969b0c56f31d383c2191954371230ae8a66cc523beb30e850daa686deb4ffe300aa3a3f5d24ff74e5b277a91cded3b0e56f7fe46c517bba9d75d41a8f")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0x85c410b9469358b4b8b420f0828f4ddfcfc533a29cf582d814a114adc79360b55960cf6d702f18d79566646c6df2285f00c5f1435e3a7673c397410e6a416614fbcb4d7e0040efa8b1993c8ab6c049d783c19741b674d580de378719688ca726")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0x8146a4b63874b62b047b03b22f1ef44611fc0f5a30b51841e3ea71c348fb30c14f95807046de2788a53f5ca9d9fc00320e6dee44f777ce709f4e30196dce6f2543cb563a4c46c731a35489e924b9352244a377e53be4efaae5aa18df511733c9")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0x91e94bb799f2a5aa2cadd728d9543c871e4879761ff6a7b26d36941d5dfad4eb3ee77b3bf0b0772e8003a983f9ae8a2406749a622873d157efa72b15359c8df3c9688528bec129cb5211fc9649bfd69be0a9ea3722c98db53828d93091b25efc")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0x979b098b4df783c2e94dd49ffc0400768b14c4a804b2e2947dbd55a65ae4c06d8cd87dd3fb81b7de795a47a7a5ef967b041b3bb1b1151a79bb15018115fe291fa2bebdb1fe6acd9f932ed8521f6959cb7415b175c82ac8378b5d47d050c8736b")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0xb111d056052dbeb60e1e9e8ebcdfc467be1b3795c3149f41fc8e4918b87e1b009dab79c5c5d7b69e83f4ddcef35f271309caa9f68a9f970166269015b5cd89ce3155c3c621bb2a9c1a2fba71c4ee915e7ef3a7db892602ee5466b853f3b62933")[])

      is_aggregator(133, ValidatorSig.fromHex(
        "0x93a284081cd6667c0944e7aaa0b71785beea9bd479b66153b9be1fd7e5c32ab4eda33139b251b655ba76ead27682ef8c008c7ab82b16f8d0d5b059725077dd58f8335ca3483223551c6eb2d13d639d74ba795dba50cf2751d99cd2d913429f9a")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0x997fdaba788cec16c7821d334583f591772c65c02a550ed428776ac7f00649cfe2006fa500cb7cc9e2479a0a9ed2a5f80a5bd3951ed5025a17e8e0f26a81c44a44c8644636268ef558949e9282f8f36417728d58dbd4e585a93e78dfde54d0c1")[])

      is_aggregator(132, ValidatorSig.fromHex(
        "0xa1e0546d5acaf84e5e108e9e23d5d2854c543142afaab5992c7544dd8934709c8c6252f9d23ce04207a1e9fca6716c660f950a9b27e1c591255f00ba2830ad7dba0d2595ae6b27106fadeff2059a6d70c32514db0d878b1dbc924058465e313d")[])

  test "isNearSyncCommitteePeriod":
    check:
      nearSyncCommitteePeriod(0.Epoch).get == 0

    for i in 1'u64 .. 20'u64:
      for j in 0'u64 .. SYNC_COMMITTEE_SUBNET_COUNT:
        check: nearSyncCommitteePeriod((EPOCHS_PER_SYNC_COMMITTEE_PERIOD * i - j).Epoch).get == j

    # Smaller values EPOCHS_PER_SYNC_COMMITTEE_PERIOD would mean the wrap-around
    # causes false test failures
    static: doAssert EPOCHS_PER_SYNC_COMMITTEE_PERIOD >= 8
    for i in 1'u64 .. 20'u64:
      for j in (SYNC_COMMITTEE_SUBNET_COUNT + 1'u64) .. 7'u64:
        check: nearSyncCommitteePeriod((EPOCHS_PER_SYNC_COMMITTEE_PERIOD * i - j).Epoch).isNone

  test "Liveness failsafe conditions":
    var x: array[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    const MAX_MISSING_CONTIGUOUS = 3
    const MAX_MISSING_WINDOW = 5
    const FAULT_INSPECTION_WINDOW = 32

    # There haven't been enough slots to trigger any of the conditions
    for i in 0 .. MAX_MISSING_CONTIGUOUS + 1:
      check: not livenessFailsafeInEffect(x, i.Slot)
    # But once there are, the default all-equals array shouldn't allow it. An
    # additional slot is gained because it's notionally not possible for some
    # genesis block not to exist.
    for i in MAX_MISSING_CONTIGUOUS + 2 .. FAULT_INSPECTION_WINDOW + 10:
      check: livenessFailsafeInEffect(x, i.Slot)

    for i in FAULT_INSPECTION_WINDOW * 2 ..< FAULT_INSPECTION_WINDOW * 3:
      x[i].data[0] = i.uint8

    # There haven't been enough slots to trigger any of the conditions; unlike
    # first round this doesn't line up with genesis-adjacent slots and doesn't
    # have that additional genesis block additional-slot-before-trigger.
    for i in
        FAULT_INSPECTION_WINDOW * 3 ..
        FAULT_INSPECTION_WINDOW * 3 + MAX_MISSING_CONTIGUOUS:
      check: not livenessFailsafeInEffect(x, i.Slot)
    for i in
        FAULT_INSPECTION_WINDOW * 3 + MAX_MISSING_CONTIGUOUS + 1 ..
        FAULT_INSPECTION_WINDOW * 4:
      check: livenessFailsafeInEffect(x, i.Slot)

    # This time, add some extant blocks to extend non-liveness-failsafe conditions
    for i in FAULT_INSPECTION_WINDOW * 4 ..< FAULT_INSPECTION_WINDOW * 5:
      x[i].data[0] = i.uint8
    # extend last entry to simulate missing blocks
    for i in
        FAULT_INSPECTION_WINDOW * 5 ..<
        FAULT_INSPECTION_WINDOW * 5 + MAX_MISSING_CONTIGUOUS:
      x[i].data[0] = (FAULT_INSPECTION_WINDOW * 5 - 1).uint8
    # next real block
    x[FAULT_INSPECTION_WINDOW * 5 + MAX_MISSING_CONTIGUOUS].data[0] = 34

    for i in
        FAULT_INSPECTION_WINDOW * 5 ..
        FAULT_INSPECTION_WINDOW * 3 + MAX_MISSING_CONTIGUOUS * 2:
      check: not livenessFailsafeInEffect(x, i.Slot)
    for i in
        FAULT_INSPECTION_WINDOW * 5 + MAX_MISSING_CONTIGUOUS * 2 + 1 ..
        FAULT_INSPECTION_WINDOW * 6:
      check: livenessFailsafeInEffect(x, i.Slot)

    # Add some all-present blocks for a few epochs
    for i in FAULT_INSPECTION_WINDOW * 6 ..< FAULT_INSPECTION_WINDOW * 9:
      x[i].data[0] = i.uint8
    static: doAssert MAX_MISSING_WINDOW > MAX_MISSING_CONTIGUOUS
    # This satisfies contiguous-missing limit, but not total-per-window limit
    for i in countup(
        FAULT_INSPECTION_WINDOW * 9,
        FAULT_INSPECTION_WINDOW * 9 + MAX_MISSING_CONTIGUOUS * 2, 2):
      x[i].data[0] = i.uint8
      x[i + 1].data[0] = i.uint8   # missing block

    for i in
        FAULT_INSPECTION_WINDOW * 7 ..
        FAULT_INSPECTION_WINDOW * 9 + MAX_MISSING_WINDOW * 2 - 1:
      # i.e. two fullly covered epochs then get into MAX_MISSING_WINDOW * 2 - 1
      # of the every-other-block is present. Because only MAX_MISSING_WINDOW of
      # these can exist, it's the ones at (FIW*9 base of 0): 1, 3, 5, 7, 9 that
      # are missing. Can get up to 9 here, i.e. by 2 * MAX_MISSING_WINDOW, as a
      # result of 50% duty cycle pattern.
      check: not livenessFailsafeInEffect(x, i.Slot)
    for i in
        FAULT_INSPECTION_WINDOW * 9 + MAX_MISSING_WINDOW * 2 ..
        FAULT_INSPECTION_WINDOW * 10:
      check: livenessFailsafeInEffect(x, i.Slot)

    # Check wraparound is sane; same mod-equivalent slots but actually near
    # genesis don't trigger liveness failures, as they clamp the inspection
    # window at element 0 of array rather than wrapping backwards.
    for i in
        SLOTS_PER_HISTORICAL_ROOT ..
        SLOTS_PER_HISTORICAL_ROOT + FAULT_INSPECTION_WINDOW:
      check: livenessFailsafeInEffect(x, i.Slot)

  test "Stability subnets":
    check:
      toSeq(compute_subscribed_subnets(default(UInt256), 0.Epoch)) ==
        @[49.SubnetId, 50.SubnetId]
      toSeq(compute_subscribed_subnets(default(UInt256), 1.Epoch)) ==
        @[49.SubnetId, 50.SubnetId]
      toSeq(compute_subscribed_subnets(default(UInt256), 2.Epoch)) ==
        @[49.SubnetId, 50.SubnetId]
      toSeq(compute_subscribed_subnets(default(UInt256), 2.Epoch)) ==
        @[49.SubnetId, 50.SubnetId]
      toSeq(compute_subscribed_subnets(default(UInt256), 200.Epoch)) ==
        @[49.SubnetId, 50.SubnetId]
      toSeq(compute_subscribed_subnets(default(UInt256), 300.Epoch)) ==
        @[16.SubnetId, 17.SubnetId]
      toSeq(compute_subscribed_subnets(default(UInt256), 400.Epoch)) ==
        @[16.SubnetId, 17.SubnetId]

  test "Index shuffling and unshuffling invert":
    const seed = Eth2Digest.fromHex(
      "0xa0054f8b4dead1ac88bd2c50cf13eab88f86d020362708a97a13012a402c57d3")

    for index_count in [1'u64, 4'u64, 52'u64, 2121'u64, 42616'u64]:
      for index in 0'u64 ..< index_count:
        check:
          compute_shuffled_index(
            compute_inverted_shuffled_index(
              index, index_count, seed), index_count, seed) == index
          compute_inverted_shuffled_index(
            compute_shuffled_index(
              index, index_count, seed), index_count, seed) == index
