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
  stew/[endians2, objects, byteutils], hashes, nimcrypto/utils,
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
  BlsValueType* = enum
    Real
    OpaqueBlob

  BlsValue*[T] = object
    # TODO This is a temporary type needed until we sort out the
    # issues with invalid BLS values appearing in the SSZ test suites.
    case kind*: BlsValueType
    of Real:
      blsValue*: T
    of OpaqueBlob:
      when T is blscurve.Signature:
        blob*: array[96, byte]
      else:
        blob*: array[48, byte]

  ValidatorPubKey* = BlsValue[blscurve.VerKey]
  # ValidatorPubKey* = blscurve.VerKey

  # ValidatorPubKey* = array[48, byte]
  # The use of byte arrays proved to be a dead end pretty quickly.
  # Plenty of code needs to be modified for a successful build and
  # the changes will negatively affect the performance.

  # ValidatorPrivKey* = BlsValue[blscurve.SigKey]
  ValidatorPrivKey* = blscurve.SigKey

  ValidatorSig* = BlsValue[blscurve.Signature]

  BlsCurveType* = VerKey|SigKey|Signature
  ValidatorPKI* = ValidatorPrivKey|ValidatorPubKey|ValidatorSig

proc init*[T](BLS: type BlsValue[T], val: auto): BLS =
  result.kind = BlsValueType.Real
  result.blsValue = init(T, val)

func `$`*(x: BlsValue): string =
  if x.kind == Real:
    $x.blsValue
  else:
    # r: is short for random. The prefix must be short
    # due to the mechanics of the `shortLog` function.
    "r:" & toHex(x.blob, true)

func `==`*(a, b: BlsValue): bool =
  if a.kind != b.kind: return false
  if a.kind == Real:
    return a.blsValue == b.blsValue
  else:
    return a.blob == b.blob

func getBytes*(x: BlsValue): auto =
  if x.kind == Real:
    getBytes x.blsValue
  else:
    x.blob

func shortLog*(x: BlsValue): string =
  ($x)[0..7]

func shortLog*(x: BlsCurveType): string =
  ($x)[0..7]

proc hash*(x: BlsValue): Hash {.inline.} =
  if x.kind == Real:
    hash x.blsValue.getBytes()
  else:
    hash x.blob

template hash*(x: BlsCurveType): Hash =
  hash(getBytes(x))

template `==`*[T](a: BlsValue[T], b: T): bool =
  a.blsValue == b

template `==`*[T](a: T, b: BlsValue[T]): bool =
  a == b.blsValue

func pubKey*(pk: ValidatorPrivKey): ValidatorPubKey =
  when ValidatorPubKey is BlsValue:
    ValidatorPubKey(kind: Real, blsValue: pk.getKey())
  elif ValidatorPubKey is array:
    pk.getKey.getBytes
  else:
    pk.getKey

proc init(T: type VerKey): VerKey =
  result.point.inf()

proc init(T: type SigKey): SigKey =
  result.point.inf()

proc combine*[T](values: openarray[BlsValue[T]]): BlsValue[T] =
  result = BlsValue[T](kind: Real, blsValue: T.init())

  for value in values:
    result.blsValue.combine(value.blsValue)

proc combine*[T](x: var BlsValue[T], other: BlsValue[T]) =
  doAssert x.kind == Real and other.kind == Real
  x.blsValue.combine(other.blsValue)

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/bls_signature.md#bls_aggregate_pubkeys
func bls_aggregate_pubkeys*(keys: openArray[ValidatorPubKey]): ValidatorPubKey =
  keys.combine()

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.1/specs/bls_signature.md#bls_verify
func bls_verify*(
    pubkey: ValidatorPubKey, msg: openArray[byte], sig: ValidatorSig,
    domain: Domain): bool =
  # name from spec!
  if sig.kind != Real:
    # Invalid signatures are possible in deposits (discussed with Danny)
    return false
  when ValidatorPubKey is BlsValue:
    if sig.kind != Real or pubkey.kind != Real:
      # TODO: chronicles warning
      return false
    # TODO bls_verify_multiple(...) used to have this workaround, and now it
    # lives here. No matter the signature, there's also no meaningful way to
    # verify it -- it's a kind of vacuous truth. No pubkey/sig pairs.
    if pubkey == ValidatorPubKey():
      return true

    sig.blsValue.verify(msg, domain, pubkey.blsValue)
  else:
    sig.verify(msg, domain, pubkey)

when ValidatorPrivKey is BlsValue:
  func bls_sign*(key: ValidatorPrivKey, msg: openarray[byte],
                 domain: Domain): ValidatorSig =
    # name from spec!
    if key.kind == Real:
      ValidatorSig(kind: Real, blsValue: key.blsValue.sign(domain, msg))
    else:
      ValidatorSig(kind: OpaqueBlob)
else:
  func bls_sign*(key: ValidatorPrivKey, msg: openarray[byte],
                 domain: Domain): ValidatorSig =
    # name from spec!
    ValidatorSig(kind: Real, blsValue: key.sign(domain, msg))

func fromBytes*[T](R: type BlsValue[T], bytes: openarray[byte]): R =
  # This is a workaround, so that we can deserialize the serialization of a
  # default-initialized BlsValue without raising an exception
  when defined(ssz_testing):
    # Only for SSZ parsing tests, everything is an opaque blob
    R(kind: OpaqueBlob, blob: toArray(result.blob.len, bytes))
  else:
    # Try if valid BLS value
    # TODO: address the side-effects in nim-blscurve
    {.noSideEffect.}:
      let success = init(result.blsValue, bytes)
    if not success:
      # TODO: chronicles trace
      result = R(kind: OpaqueBlob)
      assert result.blob.len == bytes.len
      result.blob[result.blob.low .. result.blob.high] = bytes

func fromHex*[T](R: type BlsValue[T], hexStr: string): R =
  fromBytes(R, hexToSeqByte(hexStr))

func initFromBytes*[T](val: var BlsValue[T], bytes: openarray[byte]) =
  val = fromBytes(BlsValue[T], bytes)

func initFromBytes*(val: var BlsCurveType, bytes: openarray[byte]) =
  val = init(type(val), bytes)

proc writeValue*(writer: var JsonWriter, value: ValidatorPubKey) {.inline.} =
  when value is BlsValue:
    doAssert value.kind == Real
    writer.writeValue($value.blsValue)
  else:
    writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var ValidatorPubKey) {.inline.} =
  value.initFromBytes(fromHex reader.readValue(string))

proc writeValue*(writer: var JsonWriter, value: ValidatorSig) {.inline.} =
  when value is BlsValue:
    if value.kind == Real:
      writer.writeValue($value.blsValue)
    else:
      # Workaround: https://github.com/status-im/nim-beacon-chain/issues/374
      let asHex = toHex(value.blob, true)
      # echo "[Warning] writing raw opaque signature: ", asHex
      writer.writeValue(asHex)
  else:
    writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var ValidatorSig) {.inline.} =
  value.initFromBytes(fromHex reader.readValue(string))

proc writeValue*(writer: var JsonWriter, value: ValidatorPrivKey) {.inline.} =
  when value is BlsValue:
    doAssert value.kind == Real
    writer.writeValue($value.blsValue)
  else:
    writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var ValidatorPrivKey) {.inline.} =
  value.initFromBytes(fromHex reader.readValue(string))

when ValidatorPrivKey is BlsValue:
  proc newPrivKey*(): ValidatorPrivKey =
    ValidatorPrivKey(kind: Real, blsValue: SigKey.random())
else:
  proc newPrivKey*(): ValidatorPrivKey =
    SigKey.random()

when networkBackend == rlpxBackend:
  import eth/rlp

  when ValidatorPubKey is BlsValue:
    proc append*(writer: var RlpWriter, value: ValidatorPubKey) =
      writer.append if value.kind == Real: value.blsValue.getBytes()
                    else: value.blob
  else:
    proc append*(writer: var RlpWriter, value: ValidatorPubKey) =
      writer.append value.getBytes()

  proc read*(rlp: var Rlp, T: type ValidatorPubKey): T {.inline.} =
    result.initFromBytes rlp.toBytes.toOpenArray

  when ValidatorSig is BlsValue:
    proc append*(writer: var RlpWriter, value: ValidatorSig) =
      writer.append if value.kind == Real: value.blsValue.getBytes()
                    else: value.blob
  else:
    proc append*(writer: var RlpWriter, value: ValidatorSig) =
      writer.append value.getBytes()

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

proc toGaugeValue*(hash: Eth2Digest): int64 =
  # Only the last 8 bytes are taken into consideration in accordance
  # to the ETH2 metrics spec:
  # https://github.com/ethereum/eth2.0-metrics/blob/6a79914cb31f7d54858c7dd57eee75b6162ec737/metrics.md#interop-metrics
  cast[int64](uint64.fromBytesLE(hash.data[24..31]))

template fromSszBytes*(T: type BlsValue, bytes: openarray[byte]): auto =
  fromBytes(T, bytes)

