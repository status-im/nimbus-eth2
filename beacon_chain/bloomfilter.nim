# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import "."/spec/crypto

from stew/bitops2 import getBit, setBit
from "."/spec/datatypes/base import Validator, pubkey
from "."/spec/helpers import bytes_to_uint32

const
  # https://hur.st/bloomfilter/?n=4M&p=&m=8MiB&k=
  pubkeyBloomFilterScale = 23   # 21 too small, 22 borderline, 24 also ok

type
  PubkeyBloomFilter* = object
    data: array[1 shl pubkeyBloomFilterScale, byte]

iterator bloomFilterHashes(pubkey: ValidatorPubKey): auto =
  const pubkeyBloomFilterMask = (1 shl pubkeyBloomFilterScale) - 1
  for r in countup(0'u32, 20'u32, 4'u32):
    # ValidatorPubKeys have fairly uniform entropy; using enough hash
    # functions also reduces risk of low-entropy portions
    yield pubkey.blob.toOpenArray(r, r+3).bytes_to_uint32 and
      pubkeyBloomFilterMask

template incl*(bloomFilter: var PubkeyBloomFilter, pubkey: ValidatorPubKey) =
  for bloomFilterHash in bloomFilterHashes(pubkey):
    setBit(bloomFilter.data, bloomFilterHash)

func constructBloomFilter*(x: openArray[Validator]): auto =
  let res = new PubkeyBloomFilter
  for m in x:
    incl(res[], m.pubkey)
  res

func mightContain*(
    bloomFilter: PubkeyBloomFilter, pubkey: ValidatorPubKey): bool =
  # Might return false positive, but never false negative
  for bloomFilterHash in bloomFilterHashes(pubkey):
    if not getBit(bloomFilter.data, bloomFilterHash):
      return false

  true
