# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# At the time of writing, the exact definitions of what should be used for
# cryptography in the spec is in flux, with sizes and test vectors still being
# hashed out. This layer helps isolate those chagnes.

# Useful conversation about BLS signatures (TODO: condense this)
#
#   I can probably google this somehow, but bls signatures, anyone knows off the
#   top of their head if they have to be combined one by one, or can two group
#   signatures be combined? what happens to overlap then?
#   Danny Ryan
#   @djrtwo
#   Dec 21 12:00
#   Yeah, you can do any linear combination of signatures. but you have to
#   remember the linear combination of pubkeys that constructed
#   if you have two instances of a signature from pubkey p, then you need 2*p in
#   the group pubkey
#   because the attestation bitfield is only 1 bit per pubkey right now,
#   attestations do not support this
#   it could be extended to support N overlaps up to N times per pubkey if we
#   had N bits per validator instead of 1
#   We are shying away from this for the time being. If there end up being
#   substantial difficulties in network layer aggregation, then adding bits
#   to aid in supporting overlaps is one potential solution
#   Jacek Sieka
#   @arnetheduck
#   Dec 21 12:02
#   ah nice, you anticipated my followup question there :) so it's not a
#   straight-off set union operation
#   Danny Ryan
#   @djrtwo
#   Dec 21 12:02
#   depending on the particular network level troubles we run into
#   right
#   aggregatng sigs and pubkeys are both just ec adds
#   https://github.com/ethereum/py-evm/blob/d82b10ae361cde6abbac62f171fcea7809c4e3cf/eth/_utils/bls.py#L191-L202
#   subtractions work too (i suppose this is obvious). You can linearly combine
#   sigs or pubs in any way


import
  sequtils,
  stew/objects, hashes, nimcrypto/utils,
  blscurve, json_serialization,
  ../version, digest,
  chronicles

export
  json_serialization

export
  blscurve.init, blscurve.getBytes, blscurve.combine,
  blscurve.`$`, blscurve.`==`,
  blscurve.Signature

type
  LazyBlsType* = enum
    # We want OpaqueBlob to be the default
    # - https://github.com/status-im/nim-beacon-chain/issues/412
    OpaqueBlob
    Real

  LazyBls*[T] = object
    # This is a wrapper to handle potentially invalid
    # public/private keys and signatures that we can receive or parse.
    #
    # In general in tests, in Deposits and in some state transitions
    # we get invalid data or a "zero".
    #
    # Values are lazily checked and transformed into concrete BLS value
    # on usage, to avoid a huge startup cost (if we have parse a state with
    # thousands of signatures for example or load a state from a database)
    alreadyChecked: bool
    case kind*: LazyBlsType
    # Note: this requires a temporary buffer
    #       for conversion between OpaqueBlob and Real
    of Real:
      blsValue*: T
    of OpaqueBlob:
      when T is blscurve.Signature:
        blob*: array[96, byte]
      else:
        blob*: array[48, byte]

  ValidatorPrivKey* = blscurve.SigKey
  ValidatorPubKey* = LazyBls[blscurve.VerKey]
  ValidatorSig* = LazyBls[blscurve.Signature]

  BlsCurveType* = VerKey|SigKey|Signature
  ValidatorPKI* = ValidatorPrivKey|ValidatorPubKey|ValidatorSig

proc init*[T](BLS: type LazyBls[T], val: auto): BLS =
  # Val can be T or an array of bytes
  result.kind = Real
  result.alreadyChecked = true
  result.blsValue = init(T, val)

func `$`*(x: LazyBls): string =
  if x.kind == Real:
    $x.blsValue
  else:
    # r: is short for random. The prefix must be short
    # due to the mechanics of the `shortLog` function.
    "r:" & toHex(x.blob, true)

proc unsafePromote*[T](a: LazyBls[T]) =
  ## Try promoting an opaque blob to its corresponding
  ## BLS value.
  ##
  ## ⚠️ Warning - unsafe.
  ## At a low-level we mutate the input but all API like
  ## bls_sign, bls_verify assume that their inputs are immutable

  if a.alreadyChecked:
    return
  assert a.kind == OpaqueBlob

  # Try if valid BLS value
  var buffer: T
  let success = blscurve.init(buffer, a.blob) # Stew symbol conflict: https://github.com/status-im/nim-stew/issues/9

  # # Unsafe hidden mutation of the input
  let ptr_a = a.unsafeAddr

  if true:
    ptr_a.kind = Real
    ptr_a.blsValue = buffer
  # TODO: chronicles trace
  ptr_a.alreadyChecked = true

proc `==`*(a, b: LazyBls): bool =
  # TODO: We can't unsafePromote here as it
  #       it has side-effect https://github.com/status-im/nim-blscurve/issues/27
  #       and you get ../vendor/nimbus-build-system/vendor/Nim/lib/system.nim(2474, 6) Error: '==' can have side effects
  #
  #       Furthermore, the "{.noSideEffect.}: body" syntax only exist in 0.20+
  # unsafePromote(a)
  # unsafePromote(b)
  if a.kind != b.kind:
    return false
  if a.kind == Real:
    return a.blsValue == b.blsValue
  else:
    return a.blob == b.blob

func getBytes*(x: LazyBls): auto =
  if x.kind == Real:
    getBytes x.blsValue
  else:
    x.blob

func shortLog*(x: LazyBls): string =
  ($x)[0..7]

func shortLog*(x: BlsCurveType): string =
  ($x)[0..7]

proc hash*(x: LazyBls): Hash {.inline.} =
  if x.kind == Real:
    hash x.blsValue.getBytes()
  else:
    hash x.blob

template hash*(x: BlsCurveType): Hash =
  hash(getBytes(x))

template `==`*[T](a: LazyBls[T], b: T): bool =
  a.blsValue == b

template `==`*[T](a: T, b: LazyBls[T]): bool =
  a == b.blsValue

func pubKey*(pk: ValidatorPrivKey): ValidatorPubKey =
  ValidatorPubKey(
    kind: Real,
    alreadyChecked: true,
    blsValue: pk.getKey()
  )

proc combine*[T](values: openarray[LazyBls[T]]): LazyBls[T] =
  result.kind = Real
  result.alreadyChecked = true
  init(result.blsValue)

  for i in 0 ..< values.len:
    unsafePromote(values[i])
    result.blsValue.combine(values[i].blsValue)

proc combine*[T](x: var LazyBls[T], other: LazyBls[T]) =
  doAssert x.kind == Real and other.kind == Real
  x.blsValue.combine(other.blsValue)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/bls_signature.md#bls_aggregate_pubkeys
proc bls_aggregate_pubkeys*(keys: openArray[ValidatorPubKey]): ValidatorPubKey =
  keys.combine()

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/bls_signature.md#bls_verify
proc bls_verify*(
    pubkey: ValidatorPubKey, msg: openArray[byte], sig: ValidatorSig,
    domain: Domain): bool =
  # name from spec!
  unsafePromote(sig)
  if sig.kind != Real:
    # Invalid signatures are possible in deposits (discussed with Danny)
    return false
  unsafePromote(pubkey)
  if pubkey.kind != Real:
    # TODO: chronicles warning
    return false
  sig.blsValue.verify(msg, domain, pubkey.blsValue)

# https://github.com/ethereum/eth2.0-specs/blob/v0.8.3/specs/bls_signature.md#bls_verify_multiple
proc bls_verify_multiple*(
    pubkeys: seq[ValidatorPubKey], message_hashes: openArray[Eth2Digest],
    sig: ValidatorSig, domain: Domain): bool =
  # {.noSideEffect.} - https://github.com/status-im/nim-chronicles/issues/62
  let L = len(pubkeys)
  doAssert L == len(message_hashes)
  if sig.kind != Real:
    warn "Raw bytes do not match with a BLS signature."
    return false

  # TODO optimize using multiPairing
  for pubkey_message_hash in zip(pubkeys, message_hashes):
    let (pubkey, message_hash) = pubkey_message_hash
    doAssert pubkey.kind == Real
    # TODO spec doesn't say to handle this specially, but it's silly to
    # validate without any actual public keys.
    if pubkey.blsValue == VerKey():
      trace "Received empty public key, skipping verification."
      continue
    if not sig.blsValue.verify(message_hash.data, domain, pubkey.blsValue):
      return false

  true

func bls_sign*(key: ValidatorPrivKey, msg: openarray[byte],
                domain: Domain): ValidatorSig =
  # name from spec!
  ValidatorSig(
    kind: Real,
    alreadyChecked: true,
    blsValue: key.sign(domain, msg)
  )

proc fromBytes*[T](R: type LazyBls[T], bytes: openarray[byte]): R =
  # TODO: spurious memcpy checks:
  #   - for result initialization (would need {.noInit.})
  #   - when we assign toArray to result.blob
  result.kind = OpaqueBlob
  result.blob = toArray(result.blob.len, bytes)
  when defined(ssz_testing):
    # Only for SSZ parsing tests, everything is and must stay an opaque blob
    result.alreadyChecked = true

proc initFromBytes*[T](val: var LazyBls[T], bytes: openarray[byte]) =
  val = fromBytes(LazyBls[T], bytes)

proc initFromBytes*(val: var BlsCurveType, bytes: openarray[byte]) =
  val = init(type(val), bytes)

proc writeValue*(writer: var JsonWriter, value: ValidatorPubKey) {.inline.} =
  doAssert value.kind == Real
  writer.writeValue($value.blsValue)


proc readValue*(reader: var JsonReader, value: var ValidatorPubKey) {.inline.} =
  value.initFromBytes(fromHex reader.readValue(string))

proc writeValue*(writer: var JsonWriter, value: ValidatorSig) {.inline.} =
  if value.kind == Real:
    writer.writeValue($value.blsValue)
  else:
    # Workaround: https://github.com/status-im/nim-beacon-chain/issues/374
    let asHex = toHex(value.blob, true)
    # echo "[Warning] writing raw opaque signature: ", asHex
    writer.writeValue(asHex)

proc readValue*(reader: var JsonReader, value: var ValidatorSig) {.inline.} =
  value.initFromBytes(fromHex reader.readValue(string))

proc writeValue*(writer: var JsonWriter, value: ValidatorPrivKey) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var ValidatorPrivKey) {.inline.} =
  value.initFromBytes(fromHex reader.readValue(string))

proc newPrivKey*(): ValidatorPrivKey =
  SigKey.random()

when networkBackend == rlpxBackend:
  import eth/rlp

  proc append*(writer: var RlpWriter, value: ValidatorPubKey) =
    writer.append if value.kind == Real: value.blsValue.getBytes()
                  else: value.blob

  proc read*(rlp: var Rlp, T: type ValidatorPubKey): T {.inline.} =
    result.initFromBytes rlp.toBytes.toOpenArray

  proc append*(writer: var RlpWriter, value: ValidatorSig) =
    writer.append if value.kind == Real: value.blsValue.getBytes()
                  else: value.blob

  proc read*(rlp: var Rlp, T: type ValidatorSig): T {.inline.} =
    result.initFromBytes rlp.toBytes.toOpenArray

proc writeValue*(writer: var JsonWriter, value: VerKey) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var VerKey) {.inline.} =
  value = VerKey.init(reader.readValue(string))

proc writeValue*(writer: var JsonWriter, value: Signature) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var Signature) {.inline.} =
  value = Signature.init(reader.readValue(string))
