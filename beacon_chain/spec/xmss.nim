# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

## leanXMSS signatures for the PQ fork.
##
## The scheme comes from leanVM's `lean_xmss` crate, pinned to the revision
## shared by the whole devnet (see `beacon_chain/pq/leanxmss_ffi`), through a
## small C ABI static library.
##
## https://github.com/ethereum/consensus-specs/blob/2f43bc0f989f47af81df390a90bc1f78e2436323/specs/_features/pq/beacon-chain.md#xmss-signatures

import
  std/[hashes, os],
  results, stew/[byteutils, endians2],
  json_serialization,
  ssz_serialization/codec,
  nimcrypto/[hash, sha2]

export results, json_serialization, codec

const
  XMSS_PUBKEY_SIZE* = 32
  XMSS_SIGNATURE_SIZE* = 2404
  XMSS_MESSAGE_SIZE* = 32

type
  XMSSPubkey* = object
    ## A leanXMSS public key, the Merkle root followed by the public parameter.
    blob*: array[XMSS_PUBKEY_SIZE, byte]

  XMSSSignature* = object
    ## A leanXMSS signature, the leaf index (u32 little-endian) followed by one
    ## signature per layer.
    blob*: array[XMSS_SIGNATURE_SIZE, byte]

  XMSSLeafIndex* = uint64

  LeanXmssKeyObj {.importc: "struct LeanXmssKey", incompleteStruct.} = object
  LeanXmssKeyPtr = ptr LeanXmssKeyObj

  XMSSSecretKey* = object
    ## Expanded leanXMSS secret key, owned by the Rust library.
    ## Not copyable: share it through `ref`.
    key: LeanXmssKeyPtr
    pubkey*: XMSSPubkey

  XMSSSecretKeyRef* = ref XMSSSecretKey

# ----------------------------------------------------------------------------
# Static library linkage

const
  leanXmssFfiDir = currentSourcePath.parentDir.parentDir / "pq" / "leanxmss_ffi"
  leanXmssFfiLib = leanXmssFfiDir / "target" / "release" / "libleanxmss_ffi.a"

static:
  # Build the Rust library on demand; a no-op when it is up to date.
  when not defined(leanXmssNoCargo):
    let (output, code) = gorgeEx(
      "cd " & quoteShell(leanXmssFfiDir) & " && cargo build --release 2>&1")
    if code != 0:
      raiseAssert "failed to build leanxmss_ffi:\n" & output

{.passl: leanXmssFfiLib.}
{.passl: "-lpthread -ldl -lm".}

proc leanxmss_key_gen(
  seed: ptr byte, pubkey_out: ptr byte): LeanXmssKeyPtr {.importc, cdecl.}
proc leanxmss_key_gen_many(
  seeds: ptr byte, count: csize_t, threads: csize_t, pubkeys_out: ptr byte,
  keys_out: ptr LeanXmssKeyPtr): csize_t {.importc, cdecl.}
proc leanxmss_key_free(key: LeanXmssKeyPtr) {.importc, cdecl.}
proc leanxmss_prepare(
  key: LeanXmssKeyPtr, leaf_index: uint32): cint {.importc, cdecl.}
proc leanxmss_prepare_many(
  keys: ptr LeanXmssKeyPtr, leaf_indices: ptr uint32, count: csize_t,
  threads: csize_t): csize_t {.importc, cdecl.}
proc leanxmss_sign(
  key: LeanXmssKeyPtr, message: ptr byte, leaf_index: uint32,
  signature_out: ptr byte): cint {.importc, cdecl.}
proc leanxmss_verify(
  pubkey: ptr byte, message: ptr byte,
  signature: ptr byte): cint {.importc, cdecl.}

# ----------------------------------------------------------------------------
# Key management

proc `=destroy`*(x: var XMSSSecretKey) =
  if x.key != nil:
    leanxmss_key_free(x.key)
    x.key = nil

proc `=copy`*(dest: var XMSSSecretKey, src: XMSSSecretKey) {.error.}

proc newXMSSSecretKey*(seed: openArray[byte]): Opt[XMSSSecretKeyRef] =
  ## Expands the 32-byte seed into a secret key (builds the top tree, about a
  ## second of hashing).
  if seed.len != 32:
    return Opt.none(XMSSSecretKeyRef)
  var
    seedArr: array[32, byte]
    pubkey: XMSSPubkey
  seedArr[0 ..< 32] = seed
  let key = leanxmss_key_gen(addr seedArr[0], addr pubkey.blob[0])
  if key == nil:
    return Opt.none(XMSSSecretKeyRef)
  Opt.some XMSSSecretKeyRef(key: key, pubkey: pubkey)

proc newXMSSSecretKeys*(
    seeds: openArray[array[32, byte]],
    threads = 0): seq[Opt[XMSSSecretKeyRef]] =
  ## Expands many seeds in parallel on `threads` threads (0: one per core).
  var res = newSeq[Opt[XMSSSecretKeyRef]](seeds.len)
  if seeds.len == 0:
    return res
  var
    flatSeeds = newSeq[byte](32 * seeds.len)
    pubkeys = newSeq[byte](32 * seeds.len)
    keys = newSeq[LeanXmssKeyPtr](seeds.len)
  for i, seed in seeds:
    flatSeeds[32 * i ..< 32 * (i + 1)] = seed
  discard leanxmss_key_gen_many(
    addr flatSeeds[0], csize_t(seeds.len), csize_t(threads),
    addr pubkeys[0], addr keys[0])
  for i in 0 ..< seeds.len:
    if keys[i] == nil:
      res[i] = Opt.none(XMSSSecretKeyRef)
    else:
      var pubkey: XMSSPubkey
      pubkey.blob[0 ..< 32] = pubkeys.toOpenArray(32 * i, 32 * i + 31)
      res[i] = Opt.some XMSSSecretKeyRef(key: keys[i], pubkey: pubkey)
  res

func toLeanLeaf(leaf_index: XMSSLeafIndex): Opt[uint32] =
  if leaf_index > high(uint32).uint64:
    Opt.none(uint32)
  else:
    Opt.some(leaf_index.uint32)

proc prepare*(key: XMSSSecretKeyRef, leaf_index: XMSSLeafIndex): bool =
  ## Builds and caches the bottom tree of `leaf_index`, making later signing at
  ## leaves of that tree fast.
  let leaf = toLeanLeaf(leaf_index).valueOr:
    return false
  leanxmss_prepare(key.key, leaf) == 1

proc prepareMany*(
    keys: openArray[XMSSSecretKeyRef], leaf_indices: openArray[XMSSLeafIndex],
    threads = 0): int =
  ## `prepare` for many keys in parallel on `threads` threads (0: one per
  ## core): the tree of `leaf_indices[i]` for `keys[i]`. Returns the number of
  ## trees built.
  doAssert keys.len == leaf_indices.len
  var
    ptrs: seq[LeanXmssKeyPtr]
    leaves: seq[uint32]
  for i, key in keys:
    let leaf = toLeanLeaf(leaf_indices[i]).valueOr:
      continue
    ptrs.add key.key
    leaves.add leaf
  if ptrs.len == 0:
    return 0
  int(leanxmss_prepare_many(
    addr ptrs[0], addr leaves[0], csize_t(ptrs.len), csize_t(threads)))

proc sign*(
    key: XMSSSecretKeyRef, leaf_index: XMSSLeafIndex,
    message: openArray[byte]): Opt[XMSSSignature] =
  ## `xmss.Sign(privkey, leaf_index, message)`
  if message.len != XMSS_MESSAGE_SIZE:
    return Opt.none(XMSSSignature)
  let leaf = toLeanLeaf(leaf_index).valueOr:
    return Opt.none(XMSSSignature)
  var
    msg: array[32, byte]
    sig: XMSSSignature
  msg[0 ..< 32] = message
  if leanxmss_sign(key.key, addr msg[0], leaf, addr sig.blob[0]) != 1:
    return Opt.none(XMSSSignature)
  Opt.some sig

# ----------------------------------------------------------------------------
# Verification

func getLeafIndex*(signature: XMSSSignature): XMSSLeafIndex =
  ## `xmss.GetLeafIndex(signature)`
  uint32.fromBytesLE(signature.blob.toOpenArray(0, 3)).uint64

proc verifyAnyLeaf*(
    pubkey: XMSSPubkey, message: openArray[byte],
    signature: XMSSSignature): bool =
  ## Whether `signature` is valid for `message` at the leaf it embeds.
  if message.len != XMSS_MESSAGE_SIZE:
    return false
  var
    pk = pubkey.blob
    msg: array[32, byte]
    sig = signature.blob
  msg[0 ..< 32] = message
  {.noSideEffect.}:
    leanxmss_verify(addr pk[0], addr msg[0], addr sig[0]) == 1

func verify*(
    pubkey: XMSSPubkey, leaf_index: XMSSLeafIndex, message: openArray[byte],
    signature: XMSSSignature): bool =
  ## `xmss.Verify(pubkey, leaf_index, message, signature)`
  if signature.getLeafIndex() != leaf_index:
    return false
  {.noSideEffect.}:
    verifyAnyLeaf(pubkey, message, signature)

# ----------------------------------------------------------------------------
# Conversions, SSZ, JSON

func isZero*(x: XMSSSignature | XMSSPubkey): bool =
  for b in x.blob:
    if b != 0:
      return false
  true

func `==`*(a, b: XMSSPubkey): bool = a.blob == b.blob
func `==`*(a, b: XMSSSignature): bool = a.blob == b.blob

func hash*(x: XMSSPubkey): Hash = hash(x.blob)
func hash*(x: XMSSSignature): Hash = hash(x.blob.toOpenArray(0, 63))

func toHex*(x: XMSSPubkey | XMSSSignature): string =
  "0x" & byteutils.toHex(x.blob)

func `$`*(x: XMSSPubkey | XMSSSignature): string = x.toHex()

func shortLog*(x: XMSSPubkey): string =
  byteutils.toHex(x.blob.toOpenArray(0, 3))

func shortLog*(x: XMSSSignature): string =
  "leaf:" & $x.getLeafIndex() & "/" &
    byteutils.toHex(x.blob.toOpenArray(4, 7))

func fromRaw*[T: XMSSPubkey | XMSSSignature](
    _: type T, bytes: openArray[byte]): Result[T, cstring] =
  var res: T
  if bytes.len != sizeof(res.blob):
    return err("xmss: incorrect length")
  res.blob[0 ..< bytes.len] = bytes
  ok res

func fromHex*[T: XMSSPubkey | XMSSSignature](
    _: type T, hexStr: string): Result[T, cstring] =
  let bytes =
    try:
      hexToSeqByte(hexStr)
    except ValueError:
      return err("xmss: invalid hex")
  T.fromRaw(bytes)

func toXMSSPubkey*(data: openArray[byte]): XMSSPubkey =
  ## Unchecked conversion from 32 bytes.
  doAssert data.len == XMSS_PUBKEY_SIZE
  result.blob[0 ..< XMSS_PUBKEY_SIZE] = data

func toSha256Digest*(data: openArray[byte]): array[32, byte] =
  sha256.digest(data).data

template toSszType*(v: XMSSPubkey | XMSSSignature): auto = v.blob

func fromSszBytes*(
    T: type XMSSPubkey, bytes: openArray[byte]): T {.raises: [SszError].} =
  if bytes.len != XMSS_PUBKEY_SIZE:
    raiseIncorrectSize XMSSPubkey
  result.blob[0 ..< bytes.len] = bytes

func fromSszBytes*(
    T: type XMSSSignature, bytes: openArray[byte]): T {.raises: [SszError].} =
  if bytes.len != XMSS_SIGNATURE_SIZE:
    raiseIncorrectSize XMSSSignature
  result.blob[0 ..< bytes.len] = bytes

{.pragma: serializationRaises, raises: [SerializationError, IOError].}

proc writeValue*(
    writer: var JsonWriter, value: XMSSPubkey | XMSSSignature
) {.raises: [IOError].} =
  writer.writeValue(value.toHex())

proc readValue*(
    reader: var JsonReader, value: var XMSSPubkey) {.serializationRaises.} =
  let res = XMSSPubkey.fromHex(reader.readValue(string))
  if res.isErr:
    raiseUnexpectedValue(reader, "Valid hex-encoded XMSS public key expected")
  value = res.get

proc readValue*(
    reader: var JsonReader, value: var XMSSSignature) {.serializationRaises.} =
  let res = XMSSSignature.fromHex(reader.readValue(string))
  if res.isErr:
    raiseUnexpectedValue(reader, "Valid hex-encoded XMSS signature expected")
  value = res.get
