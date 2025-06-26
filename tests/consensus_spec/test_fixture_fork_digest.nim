# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# https://github.com/ethereum/consensus-specs/blob/18387696969c0bb34e96164434a3a36edca296c9/tests/core/pyspec/eth2spec/test/fulu/validator/test_compute_fork_digest.py

{.push raises: [].}
{.used.}

import
  unittest2,
  ../../beacon_chain/spec/forks

var cfg = defaultRuntimeConfig
cfg.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
cfg.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
cfg.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
cfg.DENEB_FORK_EPOCH = GENESIS_EPOCH
cfg.ELECTRA_FORK_EPOCH = 9.Epoch
cfg.FULU_FORK_EPOCH = 100.Epoch
cfg.BLOB_SCHEDULE = @[
  BlobParameters(EPOCH: 300.Epoch, MAX_BLOBS_PER_BLOCK: 300),
  BlobParameters(EPOCH: 250.Epoch, MAX_BLOBS_PER_BLOCK: 275),
  BlobParameters(EPOCH: 200.Epoch, MAX_BLOBS_PER_BLOCK: 200),
  BlobParameters(EPOCH: 150.Epoch, MAX_BLOBS_PER_BLOCK: 175),
  BlobParameters(EPOCH: 100.Epoch, MAX_BLOBS_PER_BLOCK: 100),
  BlobParameters(EPOCH: 9.Epoch, MAX_BLOBS_PER_BLOCK: 9)]

proc cfd(
    epoch: uint64, genesis_validators_root: Eth2Digest,
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

suite "EF - Fulu - BPO forkdigests":
  test "Different lengths and blob limits":
    cfd(100, getGvr(0), [6'u8, 0, 0, 0], [0xdf'u8, 0x67, 0x55, 0x7b])
    cfd(101, getGvr(0), [6'u8, 0, 0, 0], [0xdf'u8, 0x67, 0x55, 0x7b])
    cfd(150, getGvr(0), [6'u8, 0, 0, 0], [0x8a'u8, 0xb3, 0x8b, 0x59])
    cfd(199, getGvr(0), [6'u8, 0, 0, 0], [0x8a'u8, 0xb3, 0x8b, 0x59])
    cfd(200, getGvr(0), [6'u8, 0, 0, 0], [0xd9'u8, 0xb8, 0x14, 0x38])
    cfd(201, getGvr(0), [6'u8, 0, 0, 0], [0xd9'u8, 0xb8, 0x14, 0x38])
    cfd(250, getGvr(0), [6'u8, 0, 0, 0], [0x4e'u8, 0xf3, 0x2a, 0x62])
    cfd(299, getGvr(0), [6'u8, 0, 0, 0], [0x4e'u8, 0xf3, 0x2a, 0x62])
    cfd(300, getGvr(0), [6'u8, 0, 0, 0], [0xca'u8, 0x10, 0x0d, 0x64])
    cfd(301, getGvr(0), [6'u8, 0, 0, 0], [0xca'u8, 0x10, 0x0d, 0x64])

  test "Different genesis validators roots":
    cfd(100, getGvr(1), [6'u8, 0, 0, 0], [0xfd'u8, 0x3a, 0xa2, 0xa2])
    cfd(100, getGvr(2), [6'u8, 0, 0, 0], [0x80'u8, 0xc6, 0xbd, 0x97])
    cfd(100, getGvr(3), [6'u8, 0, 0, 0], [0xf2'u8, 0x09, 0xfd, 0xfc])

  test "Different fork versions":
    cfd(100, getGvr(0), [6'u8, 0, 0, 1], [0x44'u8, 0xa5, 0x71, 0xe8])
    cfd(100, getGvr(0), [7'u8, 0, 0, 0], [0x70'u8, 0x6f, 0x46, 0x1a])
    cfd(100, getGvr(0), [7'u8, 0, 0, 1], [0x1a'u8, 0x34, 0x15, 0xc2])