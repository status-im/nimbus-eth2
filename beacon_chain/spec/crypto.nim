# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# At the time of writing, the exact definitions of what should be used for
# cryptography in the spec is in flux, with sizes and test vectors still being
# hashed out. This layer helps isolate those chagnes.

# BLS signatures can be combined such that multiple signatures are aggregated.
# Each time a new signature is added, the corresponding public key must be
# added to the verification key as well - if a key signs twice, it must be added
# twice to the verification key. Aggregated signatures can be combined
# arbitrarily (like addition) as long as public keys are aggregated in the same
# way.
#
# In eth2, we use a single bit to record which keys have signed, thus we cannot
# combined overlapping aggregates - ie if we have an aggregate of signatures of
# A, B and C, and another with B, C and D, we cannot practically combine them
# even if in theory it is possible to allow this in BLS.

# Use `-d:fake_bls` to enable fake bls verification for fuzzing and other tests.

import
  stew/[endians2, objects, byteutils], hashes, nimcrypto/utils,
  blscurve, json_serialization,
  ../version, digest,
  chronicles

export
  json_serialization

{.experimental: "codeReordering".}

# TODO(gnattishness) have the type in the main file?
# Note: not too sure about these types, so leaving untouched for now
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

when not defined(fake_bls):
  # Real bls interface implementation
  export
    blscurve.init, blscurve.getBytes, blscurve.combine,
    blscurve.`$`, blscurve.`==`,
    blscurve.Signature

  func `==`*(a, b: BlsValue): bool =
    if a.kind != b.kind: return false
    if a.kind == Real:
      return a.blsValue == b.blsValue
    else:
      return a.blob == b.blob

  template `==`*[T](a: BlsValue[T], b: T): bool =
    a.blsValue == b

  template `==`*[T](a: T, b: BlsValue[T]): bool =
    a == b.blsValue

  proc init*[T](BLS: type BlsValue[T], val: auto): BLS =
    result.kind = BlsValueType.Real
    result.blsValue = init(T, val)

  func combine*[T](values: openarray[BlsValue[T]]): BlsValue[T] =
    # TODO(gnattishness) this would also crash if an entry in the list is an OpaqueBlob kind
    # so doesn't have a `blsValue`?
    result = BlsValue[T](kind: Real, blsValue: T.init())

    for value in values:
      # TODO(gnattishness) correct would be this instead?
      # or assert that they are all Real
      # result.combine(value)
      result.blsValue.combine(value.blsValue)

  func combine*[T](x: var BlsValue[T], other: BlsValue[T]) =
    doAssert x.kind == Real and other.kind == Real
    x.blsValue.combine(other.blsValue)

  # https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/bls_signature.md#bls_verify
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
      if pubkey == default(ValidatorPubKey):
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
        doAssert result.blob.len == bytes.len
        result.blob[result.blob.low .. result.blob.high] = bytes

else:
  # Fake bls interface, useful for fuzz and other testing
  {.warning: "Fake bls verification enabled. Do not use in production code!".}
  # TODO have explicit fake_bls_verify etc names that are aliased to bls_verify etc
  # once https://github.com/nim-lang/Nim/pull/11992 is accepted

  # Export these as-is
  export
    blscurve.init, blscurve.getBytes,
    blscurve.`$`, blscurve.`==`,
    blscurve.Signature

  func `==`*(a, b: BlsValue): bool =
    # convert both to bytes and compare
    # don't care about kind
    #return toOpenArray(a.getBytes()) == toOpenArray(b.getBytes())
    return a.getBytes() == b.getBytes()

  template `==`*[T](a: BlsValue[T], b: T): bool =
    # allow comparison between curve and opaque blob
    #a == BlsValue[T](kind: OpaqueBlob, blob: b.getBytes())
    a.getBytes == b.getBytes

  template `==`*[T](a: T, b: BlsValue[T]): bool =
    # allow comparison between curve and opaque blob
    # BlsValue[T](kind: OpaqueBlob, blob: a.getBytes()) == b
    a.getBytes == b.getBytes

  # Modified interface exported from blscurve in "real" implementation

  proc combine*(sig1: var Signature, sig2: Signature) =
    ## Aggregates signature ``sig2`` into ``sig1``.
    ##
    ## Fake bls: do nothing!
    discard

  proc combine*(sigs: openarray[Signature]): Signature =
    ## Aggregates array of signatures ``sigs`` and return aggregated signature.
    ##
    ## Array ``sigs`` must not be empty!
    # NOTE: Eth2 v0.9.3 spec defines aggregate to be infinity when an empty list is passed
    # but draft spec doesn't define aggregation for an empty list
    doAssert(len(sigs) > 0)
    # Fake bls: return the first sig
    result = sigs[0]

  proc combine*(key1: var VerKey, key2: VerKey) =
    ## Aggregates verification key ``key2`` into ``key1``.
    ##
    ## Fake bls: do nothing!
    discard

  proc combine*(keys: openarray[VerKey]): VerKey =
    ## Aggregates array of verification keys ``keys`` and return aggregated
    ## verification key.
    ##
    ## Array ``keys`` must not be empty!
    # NOTE: Eth2 v0.9.3 spec defines aggregate to be infinity when an empty list is passed
    # but draft spec doesn't define aggregation for an empty list
    doAssert(len(keys) > 0)
    # Fake bls: return the first key
    result = keys[0]

  # Section corresponding to real crypto.nim

  proc init*[T](BLS: type BlsValue[T], val: auto): BLS =
    # keep as opaque bytes
    result.kind = BlsValueType.OpaqueBlob
    let t: T = T.init(val)
    result.blob = t.getBytes()

  proc init*[T](BLS: type BlsValue[T], data: openarray[byte]): BLS =
    # specializations that avoids first converting to T
    result.kind = BlsValueType.OpaqueBlob
    result.blob = toArray(result.blob.len, data)

  proc init*[T](BLS: type BlsValue[T], data: string): BLS =
    # specialization that avoids first converting to T
    result = BLS.init(fromHex(data))

  # Fake verify always returns `true`
  func bls_verify*(
      pubkey: ValidatorPubKey, msg: openarray[byte], sig: ValidatorSig,
      domain: Domain): bool = true

  func combine*[T](values: openarray[BlsValue[T]]): BlsValue[T] =
    if len(values) == 0:
      # empty so return infinity
      result = BlsValue[T](kind: OpaqueBlob, blob: T.init.getBytes)
    else:
      # return first value
      # TODO convert to opaque blob?
      result = values[0]

  func combine*[T](x: var BlsValue[T], other: BlsValue[T]) =
    # do nothing!
    discard

  func bls_sign*(key: ValidatorPrivKey, msg: openarray[byte],
                 domain: Domain): ValidatorSig =
    # name from spec!
    # Return empty signature, ignore key kinds
    ValidatorSig(kind: OpaqueBlob)

  func fromBytes*[T](R: type BlsValue[T], bytes: openarray[byte]): R =
    # Everything is an opaque blob - allows comparison but don't care about verification
    R(kind: OpaqueBlob, blob: toArray(result.blob.len, bytes))

# Implementation common to both real and fake

func initFromBytes*[T](val: var BlsValue[T], bytes: openarray[byte]) =
  val = fromBytes(BlsValue[T], bytes)

func initFromBytes*(val: var BlsCurveType, bytes: openarray[byte]) =
  val = init(type(val), bytes)

func `$`*(x: BlsValue): string =
  if x.kind == Real:
    $x.blsValue
  else:
    # r: is short for random. The prefix must be short
    # due to the mechanics of the `shortLog` function.
    "r:" & toHex(x.blob, true)

when ValidatorPrivKey is BlsValue:
  proc newPrivKey*(): ValidatorPrivKey =
    ValidatorPrivKey(kind: Real, blsValue: SigKey.random())
else:
  proc newPrivKey*(): ValidatorPrivKey =
    SigKey.random()

func getBytes*(x: BlsValue): auto =
  if x.kind == Real:
    getBytes x.blsValue
  else:
    x.blob

func shortLog*(x: BlsValue): string =
  ($x)[0..7]

func shortLog*(x: BlsCurveType): string =
  ($x)[0..7]

func hash*(x: BlsValue): Hash {.inline.} =
  if x.kind == Real:
    hash x.blsValue.getBytes()
  else:
    hash x.blob

template hash*(x: BlsCurveType): Hash =
  hash(getBytes(x))

# TODO(gnattishness) is the ``type`` here equiv to typof(SigKey) or typedesc[SigKey]?
# Ans: i think ``typeof(SigKey)`` with https://nim-lang.github.io/Nim/manual.html#procedures-command-invocation-syntax
# TODO(gnattishness) Why have these here when there's already a similar one in blscurve?
# Ans: I think because this is a ``func`` and can be used in other pure functions
func init(T: type VerKey): VerKey =
  result.point.inf()

func init(T: type SigKey): SigKey =
  # TODO(gnattishness) confirm correct impl
  # See https://github.com/status-im/nim-beacon-chain/issues/664
  result.x.zero()

func init(T: type Signature): Signature =
  result.point.inf()

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/bls_signature.md#bls_aggregate_pubkeys
func bls_aggregate_pubkeys*(keys: openArray[ValidatorPubKey]): ValidatorPubKey =
  keys.combine()

# https://github.com/ethereum/eth2.0-specs/blob/v0.9.4/specs/bls_signature.md#bls_aggregate_signatures
func bls_aggregate_signatures*(keys: openArray[ValidatorSig]): ValidatorSig =
  keys.combine()

func fromHex*[T](R: type BlsValue[T], hexStr: string): R =
  fromBytes(R, hexToSeqByte(hexStr))

func pubKey*(pk: ValidatorPrivKey): ValidatorPubKey =
  # Tests require an actual (or at least unique) corresponding pubkey be created from this
  # e.g. MakeInitialDeposits
  # if a performance issue for fake_bls, can create some other dummy e.g. based on the hash
  # or bytes of the PrivKey
  when ValidatorPubKey is BlsValue:
    ValidatorPubKey(kind: Real, blsValue: pk.getKey())
  elif ValidatorPubKey is array:
    pk.getKey.getBytes
  else:
    pk.getKey


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

when networkBackend == rlpx:
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
