# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Consensus hash function / digest
#
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#hash
#
# In Phase 0 the beacon chain is deployed with SHA256 (SHA2-256).
# Note that is is different from Keccak256 (often mistakenly called SHA3-256)
# and SHA3-256.
#
# In execution, the default hash function is Keccak256,
# and SHA256 is available as a precompiled contract.
#
# In our code base, to enable a smooth transition
# (already did Blake2b --> Keccak256 --> SHA2-256),
# we call this function `eth2digest` and it outputs `Eth2Digest`. Easy to sed :)

{.push raises: [].}

import
  # Standard library
  std/hashes,
  # Status libraries
  chronicles,
  nimcrypto/[sha2, hash],
  stew/[arrayops, byteutils, endians2, objects],
  json_serialization

from nimcrypto/utils import burnMem

export
  # Exports from sha2 / hash are explicit to avoid exporting upper-case `$` and
  # constant-time `==`
  hash.fromHex, json_serialization

type
  Eth2Digest* = MDigest[32 * 8] ## `hash32` from spec

const PREFER_BLST_SHA256* {.booldefine.} = true

when PREFER_BLST_SHA256:
  import blscurve
  when BLS_BACKEND == BLST:
    const USE_BLST_SHA256 = true
  else:
    const USE_BLST_SHA256 = false
else:
  import nimcrypto/sha2
  const USE_BLST_SHA256 = false

when USE_BLST_SHA256:
  export blscurve.update, blscurve.finish

  type Eth2DigestCtx* = BLST_SHA256_CTX

  # HMAC support
  template hmacSizeBlock*(_: type BLST_SHA256_CTX): untyped = 64
  template sizeDigest*(_: BLST_SHA256_CTX): untyped = 32

  proc finish*(ctx: var BLST_SHA256_CTX,
               data: var openArray[byte]): uint =
      var tmp {.noinit.}: array[32, byte]
      finalize(tmp, ctx)
      data.copyFrom(tmp).uint * 8
  proc clear*(ctx: var BLST_SHA256_CTX) =
    burnMem(ctx)

else:
  export sha2.update, sha2.finish
  type Eth2DigestCtx* = sha2.sha256

func `$`*(x: Eth2Digest): string =
  x.data.toHex()

func shortLog*(x: Eth2Digest): string =
  x.data.toOpenArray(0, 3).toHex()

chronicles.formatIt Eth2Digest:
  shortLog(it)

# TODO: expose an in-place digest function
#       when hashing in loop or into a buffer
#       See: https://github.com/cheatfate/nimcrypto/blob/b90ba3abd/nimcrypto/sha2.nim#L570
func eth2digest*(v: openArray[byte]): Eth2Digest {.noinit.} =
  ## Apply the Eth2 Hash function
  ## Do NOT use for secret data.
  when USE_BLST_SHA256:
    # BLST has a fast assembly optimized SHA256
    result.data.bls_sha256_digest(v)
  else:
    # We use the init-update-finish interface to avoid
    # the expensive burning/clearing memory (20~30% perf)
    var ctx {.noinit.}: Eth2DigestCtx
    ctx.init()
    ctx.update(v)
    ctx.finish()

template withEth2Hash*(body: untyped): Eth2Digest =
  ## This little helper will init the hash function and return the sliced
  ## hash:
  ## let hashOfData = withHash: h.update(data)
  when nimvm:
    # In SSZ, computeZeroHashes require compile-time SHA256
    block:
      var h {.inject.}: sha256
      init(h)
      body
      finish(h)
  else:
    when USE_BLST_SHA256:
      block:
        var h {.inject, noinit.}: Eth2DigestCtx
        init(h)
        body
        var res {.noinit.}: Eth2Digest
        finalize(res.data, h)
        res
    else:
      block:
        var h {.inject, noinit.}: Eth2DigestCtx
        init(h)
        body
        finish(h)

template hash*(x: Eth2Digest): Hash =
  ## Hash for digests for Nim hash tables
  # digests are already good hashes
  var h {.noinit.}: Hash
  copyMem(addr h, unsafeAddr x.data[0], static(sizeof(Hash)))
  h

func `==`*(a, b: Eth2Digest): bool =
  when nimvm:
    a.data == b.data
  else:
    # nimcrypto uses a constant-time comparison for all MDigest types which for
    # Eth2Digest is unnecessary - the type should never hold a secret!
    equalMem(unsafeAddr a.data[0], unsafeAddr b.data[0], sizeof(a.data))

func isZero*(x: Eth2Digest): bool =
  x.isZeroMemory

proc writeValue*(w: var JsonWriter, a: Eth2Digest) {.raises: [IOError].} =
  w.writeValue $a

proc readValue*(r: var JsonReader, a: var Eth2Digest) {.raises: [IOError, SerializationError].} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

func strictParse*(T: type Eth2Digest, hexStr: openArray[char]): T
                 {.raises: [ValueError].} =
  ## TODO We use this local definition because the string parsing functions
  ##      provided by nimcrypto are currently too lax in their requirements
  ##      for the input string. Invalid strings are silently ignored.
  hexToByteArrayStrict(hexStr, result.data)

func toGaugeValue*(hash: Eth2Digest): int64 =
  # Only the last 8 bytes are taken into consideration in accordance
  # to the ETH2 metrics spec:
  # https://github.com/ethereum/beacon-metrics/blob/6a79914cb31f7d54858c7dd57eee75b6162ec737/metrics.md#interop-metrics
  cast[int64](uint64.fromBytesLE(hash.data.toOpenArray(24, 31)))
