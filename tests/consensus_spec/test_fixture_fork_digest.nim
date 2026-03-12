# beacon_chain
# Copyright (c) 2020-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../../beacon_chain/spec/forks,
  ../../beacon_chain/spec/network

var cfg = defaultRuntimeConfig
cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
cfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
cfg.DENEB_FORK_EPOCH = GENESIS_EPOCH
cfg.ELECTRA_FORK_EPOCH = 2.Epoch
cfg.FULU_FORK_EPOCH = 3.Epoch
cfg.BLOB_SCHEDULE = @[
  BlobParameters(EPOCH: 8.Epoch, MAX_BLOBS_PER_BLOCK: 12),
  BlobParameters(EPOCH: 7.Epoch, MAX_BLOBS_PER_BLOCK: 10),
  BlobParameters(EPOCH: 6.Epoch, MAX_BLOBS_PER_BLOCK: 9),
  BlobParameters(EPOCH: 5.Epoch, MAX_BLOBS_PER_BLOCK: 8),
  BlobParameters(EPOCH: 3.Epoch, MAX_BLOBS_PER_BLOCK: 6),
  BlobParameters(EPOCH: 1.Epoch, MAX_BLOBS_PER_BLOCK: 3)]

proc cfd(
    cfg: RuntimeConfig, epoch: uint64, genesis_validators_root: Eth2Digest,
    fork_version: array[4, byte], expected: array[4, byte]) =
  var cfg = cfg
  cfg.FULU_FORK_VERSION = Version(fork_version)
  check:
    ForkDigest(expected) == atEpoch(
      ForkDigests.init(cfg, genesis_validators_root), epoch.Epoch, cfg)
    ForkDigest(expected) == compute_fork_digest_fulu(
      cfg, genesis_validators_root, epoch.Epoch)

func getGvr(filling: uint8): Eth2Digest =
  var res: Eth2Digest
  for i in 0 ..< res.data.len:
    res.data[i] = filling
  res

suite "EF - BPO forkdigests":
  var bpoCfg = defaultRuntimeConfig
  bpoCfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
  bpoCfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
  bpoCfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
  bpoCfg.DENEB_FORK_EPOCH = GENESIS_EPOCH
  bpoCfg.ELECTRA_FORK_EPOCH = 9.Epoch
  bpoCfg.FULU_FORK_EPOCH = 100.Epoch
  bpoCfg.BLOB_SCHEDULE = @[
    BlobParameters(EPOCH: 300.Epoch, MAX_BLOBS_PER_BLOCK: 300),
    BlobParameters(EPOCH: 250.Epoch, MAX_BLOBS_PER_BLOCK: 275),
    BlobParameters(EPOCH: 200.Epoch, MAX_BLOBS_PER_BLOCK: 200),
    BlobParameters(EPOCH: 150.Epoch, MAX_BLOBS_PER_BLOCK: 175),
    BlobParameters(EPOCH: 100.Epoch, MAX_BLOBS_PER_BLOCK: 100),
    BlobParameters(EPOCH: 9.Epoch, MAX_BLOBS_PER_BLOCK: 9)]

  test "Different lengths and blob limits":
    bpoCfg.cfd(100, getGvr(0), [6'u8, 0, 0, 0], [0xdf'u8, 0x67, 0x55, 0x7b])
    bpoCfg.cfd(101, getGvr(0), [6'u8, 0, 0, 0], [0xdf'u8, 0x67, 0x55, 0x7b])
    bpoCfg.cfd(150, getGvr(0), [6'u8, 0, 0, 0], [0x8a'u8, 0xb3, 0x8b, 0x59])
    bpoCfg.cfd(199, getGvr(0), [6'u8, 0, 0, 0], [0x8a'u8, 0xb3, 0x8b, 0x59])
    bpoCfg.cfd(200, getGvr(0), [6'u8, 0, 0, 0], [0xd9'u8, 0xb8, 0x14, 0x38])
    bpoCfg.cfd(201, getGvr(0), [6'u8, 0, 0, 0], [0xd9'u8, 0xb8, 0x14, 0x38])
    bpoCfg.cfd(250, getGvr(0), [6'u8, 0, 0, 0], [0x4e'u8, 0xf3, 0x2a, 0x62])
    bpoCfg.cfd(299, getGvr(0), [6'u8, 0, 0, 0], [0x4e'u8, 0xf3, 0x2a, 0x62])
    bpoCfg.cfd(300, getGvr(0), [6'u8, 0, 0, 0], [0xca'u8, 0x10, 0x0d, 0x64])
    bpoCfg.cfd(301, getGvr(0), [6'u8, 0, 0, 0], [0xca'u8, 0x10, 0x0d, 0x64])

  test "Different genesis validators roots":
    bpoCfg.cfd(100, getGvr(1), [6'u8, 0, 0, 0], [0xfd'u8, 0x3a, 0xa2, 0xa2])
    bpoCfg.cfd(100, getGvr(2), [6'u8, 0, 0, 0], [0x80'u8, 0xc6, 0xbd, 0x97])
    bpoCfg.cfd(100, getGvr(3), [6'u8, 0, 0, 0], [0xf2'u8, 0x09, 0xfd, 0xfc])

  test "Different fork versions":
    bpoCfg.cfd(100, getGvr(0), [6'u8, 0, 0, 1], [0x44'u8, 0xa5, 0x71, 0xe8])
    bpoCfg.cfd(100, getGvr(0), [7'u8, 0, 0, 0], [0x70'u8, 0x6f, 0x46, 0x1a])
    bpoCfg.cfd(100, getGvr(0), [7'u8, 0, 0, 1], [0x1a'u8, 0x34, 0x15, 0xc2])

  test "nextForkEpochAtEpoch includes Gloas from Fulu":
    var cfg = cfg
    cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
    cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    cfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
    cfg.DENEB_FORK_EPOCH = GENESIS_EPOCH
    cfg.ELECTRA_FORK_EPOCH = GENESIS_EPOCH
    cfg.FULU_FORK_EPOCH = GENESIS_EPOCH
    cfg.GLOAS_FORK_EPOCH = 1.Epoch
    cfg.BLOB_SCHEDULE = @[
      BlobParameters(EPOCH: 0.Epoch, MAX_BLOBS_PER_BLOCK: 15)]

    check:
      cfg.nextForkEpochAtEpoch(0.Epoch) == 1.Epoch
      cfg.nextForkEpochAtEpoch(1.Epoch) == FAR_FUTURE_EPOCH

  test "nextForkEpochAtEpoch with BPO before Gloas":
    var cfg = cfg
    cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
    cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    cfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
    cfg.DENEB_FORK_EPOCH = GENESIS_EPOCH
    cfg.ELECTRA_FORK_EPOCH = GENESIS_EPOCH
    cfg.FULU_FORK_EPOCH = GENESIS_EPOCH
    cfg.GLOAS_FORK_EPOCH = 10.Epoch
    cfg.BLOB_SCHEDULE = @[
      BlobParameters(EPOCH: 5.Epoch, MAX_BLOBS_PER_BLOCK: 20),
      BlobParameters(EPOCH: 0.Epoch, MAX_BLOBS_PER_BLOCK: 15)]

    check:
      # At epoch 0 (Fulu), next fork is BPO at epoch 5 (before Gloas at 10)
      cfg.nextForkEpochAtEpoch(0.Epoch) == 5.Epoch
      # At epoch 5 (Fulu), next fork is Gloas at epoch 10
      cfg.nextForkEpochAtEpoch(5.Epoch) == 10.Epoch
      # At epoch 10 (Gloas), no future BPOs or forks
      cfg.nextForkEpochAtEpoch(10.Epoch) == FAR_FUTURE_EPOCH

  test "ENR fork ID transitions from Fulu to Gloas":
    var cfg = cfg
    cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
    cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    cfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
    cfg.DENEB_FORK_EPOCH = GENESIS_EPOCH
    cfg.ELECTRA_FORK_EPOCH = GENESIS_EPOCH
    cfg.FULU_FORK_EPOCH = GENESIS_EPOCH
    cfg.FULU_FORK_VERSION = Version([0x70'u8, 0, 0, 0x38])
    cfg.GLOAS_FORK_EPOCH = 1.Epoch
    cfg.GLOAS_FORK_VERSION = Version([0x80'u8, 0, 0, 0x38])
    cfg.BLOB_SCHEDULE = @[
      BlobParameters(EPOCH: 0.Epoch, MAX_BLOBS_PER_BLOCK: 15)]
    let gvr = Eth2Digest.fromHex("0x8488a6ea91e921a17cc3af3a9d79682ef38eb7c39da786e849b31feedd2aba6f")

    let
      fuluENR = cfg.getENRForkID(0.Epoch, gvr)
      gloasENR = cfg.getENRForkID(1.Epoch, gvr)

    check:
      # At Fulu epoch, next fork version should be Gloas
      fuluENR.next_fork_version == Version([0x80'u8, 0, 0, 0x38])
      fuluENR.next_fork_epoch == 1.Epoch
      # At Gloas epoch, no next fork
      gloasENR.next_fork_version == Version([0x80'u8, 0, 0, 0x38])
      gloasENR.next_fork_epoch == FAR_FUTURE_EPOCH
      # Fork digests should differ between Fulu and Gloas
      fuluENR.fork_digest != gloasENR.fork_digest
