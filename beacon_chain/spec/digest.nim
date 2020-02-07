# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Serenity hash function / digest
#
# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#hash
#
# In Phase 0 the beacon chain is deployed with SHA256 (SHA2-256).
# Note that is is different from Keccak256 (often mistakenly called SHA3-256)
# and SHA3-256.
#
# In Eth1.0, the default hash function is Keccak256 and SHA256 is available as a precompiled contract.
#
# In our code base, to enable a smooth transition
# (already did Blake2b --> Keccak256 --> SHA2-256),
# we call this function `eth2hash`, and it outputs a `Eth2Digest`. Easy to sed :)

import
  chronicles, json_serialization,
  nimcrypto/[sha2, hash, utils],
  hashes

export
  hash.`$`, json_serialization

type
  Eth2Digest* = MDigest[32 * 8] ## `hash32` from spec
  Eth2Hash* = sha256            ## Context for hash function

chronicles.formatIt Eth2Digest:
  mixin toHex
  it.data[0..3].toHex(true)

func shortLog*(x: Eth2Digest): string =
  x.data[0..3].toHex(true)

# TODO: expose an in-place digest function
#       when hashing in loop or into a buffer
#       See: https://github.com/cheatfate/nimcrypto/blob/b90ba3abd/nimcrypto/sha2.nim#L570
func eth2hash*(v: openArray[byte]): Eth2Digest {.inline.} =
  # We use the init-update-finish interface to avoid
  # the expensive burning/clearing memory (20~30% perf)
  # TODO: security implication?
  var ctx: sha256
  ctx.init()
  ctx.update(v)
  ctx.finish()

func update*(ctx: var Sha2Context; digest: Eth2Digest) =
  ctx.update digest.data

template withEth2Hash*(body: untyped): Eth2Digest =
  ## This little helper will init the hash function and return the sliced
  ## hash:
  ## let hashOfData = withHash: h.update(data)
  var h  {.inject.}: sha256
  init(h)
  body
  var res = finish(h)
  res

func hash*(x: Eth2Digest): Hash =
  ## Hash for digests for Nim hash tables
  # Stub for BeaconChainDB

  # We just slice the first 4 or 8 bytes of the block hash
  # depending of if we are on a 32 or 64-bit platform
  result = cast[ptr Hash](unsafeAddr x)[]

proc writeValue*(writer: var JsonWriter, value: Eth2Digest) =
  writeValue(writer, value.data.toHex(true))

proc readValue*(reader: var JsonReader, value: var Eth2Digest) =
  value = Eth2Digest.fromHex(reader.readValue(string))
