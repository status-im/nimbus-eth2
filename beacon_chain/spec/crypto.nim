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

import
  # Internal
  ./digest,
  # Status
  stew/[endians2, objects, byteutils],
  nimcrypto/[utils, sysrand],
  blscurve, json_serialization,
  chronicles,
  # Standard library
  hashes

export
  json_serialization

# export
#   blscurve.init, blscurve.getBytes, blscurve.combine,
#   blscurve.`$`, blscurve.`==`,
#   blscurve.Signature

# Type definitions
# ----------------------------------------------------------------------

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

  ValidatorPubKey* = BlsValue[blscurve.PublicKey]
    # Alternatives
    # ValidatorPubKey* = blscurve.PublicKey
    # ValidatorPubKey* = array[48, byte]
    # The use of byte arrays proved to be a dead end pretty quickly.
    # Plenty of code needs to be modified for a successful build and
    # the changes will negatively affect the performance.

  ValidatorPrivKey* = blscurve.SecretKey
    # ValidatorPrivKey* = BlsValue[blscurve.SecretKey]

  ValidatorSig* = BlsValue[blscurve.Signature]

  BlsCurveType* = PublicKey|SecretKey|Signature
  ValidatorPKI* = ValidatorPrivKey|ValidatorPubKey|ValidatorSig

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

# API
# ----------------------------------------------------------------------
# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#bls-signatures

func pubKey*(privkey: ValidatorPrivKey): ValidatorPubKey =
  ## Create a private key from a public key
  # Un-specced in either hash-to-curve or Eth2
  # TODO: Test suite should use `keyGen` instead
  when ValidatorPubKey is BlsValue:
    ValidatorPubKey(kind: Real, blsValue: privkey.privToPub())
  elif ValidatorPubKey is array:
    privkey.getKey.getBytes
  else:
    privkey.getKey

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#bls-signatures
func aggregate*[T](values: openarray[ValidatorSig]): ValidatorSig =
  ## Aggregate arrays of sequences of Validator Signatures
  ## This assumes that they are real signatures

  result = BlsValue[T](kind: Real, blsValue: values[0].BlsValue)

  for i in 1 ..< values.len:
    result.blsValue.aggregate(values[i].blsValue)

func aggregate*(x: var ValidatorSig, other: ValidatorSig) =
  ## Aggregate 2 Validator Signatures
  ## This assumes that they are real signatures
  x.blsValue.aggregate(other.blsValue)

# https://github.com/ethereum/eth2.0-specs/blob/v0.10.1/specs/phase0/beacon-chain.md#bls-signatures
func blsVerify*(
    pubkey: ValidatorPubKey, message: openArray[byte],
    signature: ValidatorSig): bool =
  ## Check that a signature is valid for a message
  ## under the provided public key.
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  if signature.kind != Real:
    # Invalid signatures are possible in deposits (discussed with Danny)
    return false
  if pubkey.kind != Real:
    # TODO: chronicles warning
    return false

  # TODO: remove fully if the comment below is not true anymore and
  #       and we don't need this workaround
  # # TODO bls_verify_multiple(...) used to have this workaround, and now it
  # # lives here. No matter the signature, there's also no meaningful way to
  # # verify it -- it's a kind of vacuous truth. No pubkey/sig pairs. Sans a
  # # getBytes() or similar mechanism, pubKey == default(ValidatorPubKey) is
  # # a way to create many false positive matches. This seems odd.
  # if pubkey.getBytes() == default(ValidatorPubKey).getBytes():
  #   return true
  pubkey.blsValue.verify(message, signature.blsValue)

func blsSign*(privkey: ValidatorPrivKey, message: openarray[byte]): ValidatorSig =
  ## Computes a signature from a secret key and a message
  ValidatorSig(kind: Real, blsValue: privkey.sign(message))

func blsFastAggregateVerify*[T: byte|char](
       publicKeys: openarray[ValidatorPubKey],
       message: openarray[T],
       signature: ValidatorSig
     ): bool =
  ## Verify the aggregate of multiple signatures on the same message
  ## This function is faster than AggregateVerify
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  # TODO: Note: `invalid` in the following paragraph means invalid by construction
  #             The keys/signatures are not even points on the elliptic curves.
  #       To respect both the IETF API and the fact that
  #       we can have invalid public keys (as in not point on the elliptic curve),
  #       requiring a wrapper indirection,
  #       we need a first pass to extract keys from the wrapper
  #       and then call fastAggregateVerify.
  #       Instead:
  #         - either we expose a new API: context + init-update-finish
  #           in blscurve which already exists internally
  #         - or at network/databases/serialization boundaries we do not
  #           allow invalid BLS objects to pollute consensus routines
  if signature.kind != Real:
    return false
  var unwrapped: seq[PublicKey]
  for pubkey in publicKeys:
    if pubkey.kind != Real:
      return false
    unwrapped.add pubkey.blsValue
  return fastAggregateVerify(unwrapped, message, signature.blsValue)

proc newKeyPair*(): tuple[pub: ValidatorPubKey, priv: ValidatorPrivKey] {.noInit.}=
  ## Generates a new public-private keypair
  ## This requires entropy on the system
  # The input-keying-material requires 32 bytes at least for security
  # The generation is deterministic and the input-keying-material
  # must be protected against side-channel attacks

  var ikm: array[32, byte]
  let written = randomBytes(ikm)
  doAssert written >= 32, "Key generation failure"

  result.pub = ValidatorPubKey(kind: Real)
  doAssert keyGen(ikm, result.pub.blsValue, result.priv), "Key generation failure"

# Logging
# ----------------------------------------------------------------------

func shortLog*(x: BlsValue): string =
  ($x)[0..7]

func shortLog*(x: BlsCurveType): string =
  ($x)[0..7]

proc toGaugeValue*(hash: Eth2Digest): int64 =
  # Only the last 8 bytes are taken into consideration in accordance
  # to the ETH2 metrics spec:
  # https://github.com/ethereum/eth2.0-metrics/blob/6a79914cb31f7d54858c7dd57eee75b6162ec737/metrics.md#interop-metrics
  cast[int64](uint64.fromBytesLE(hash.data[24..31]))

# Codecs
# ----------------------------------------------------------------------

func `$`*(x: BlsValue): string =
  if x.kind == Real:
    "r: 0x" & x.blsValue.toHex()
  else:
    # r: is short for random. The prefix must be short
    # due to the mechanics of the `shortLog` function.
    "r: 0x" & x.blob.toHex(lowercase = true)

func getBytes*(x: BlsValue): auto =
  if x.kind == Real:
    x.blsValue.exportRaw()
  else:
    x.blob

func initFromBytes[T](val: var BlsValue[T], bytes: openarray[byte]) =
  # This is a workaround, so that we can deserialize the serialization of a
  # default-initialized BlsValue without raising an exception
  when defined(ssz_testing):
    # Only for SSZ parsing tests, everything is an opaque blob
    R(kind: OpaqueBlob, blob: toArray(result.blob.len, bytes))
  else:
    # Try if valid BLS value
    # TODO: address the side-effects in nim-blscurve
    val = BlsValue[T](kind: Real)
    let success = val.blsValue.fromBytes(bytes)
    if not success:
      # TODO: chronicles trace
      val = BlsValue[T](kind: OpaqueBlob)
      val.blob[val.blob.low .. val.blob.high] = bytes

func initFromBytes*(val: var ValidatorPrivKey, bytes: openarray[byte]) {.inline.} =
  discard val.fromBytes(bytes)

func fromBytes[T](R: type BlsValue[T], bytes: openarray[byte]): R {.inline.}=
  result.initFromBytes(bytes)

func fromHex*[T](R: var BlsValue[T], hexStr: string) {.inline.} =
  ## Initialize a BLSValue from its hex representation
  R.fromBytes(hexStr.hexToSeqByte())

# Hashing
# ----------------------------------------------------------------------

func hash*(x: BlsValue): Hash {.inline.} =
  # TODO: we can probably just slice the BlsValue
  if x.kind == Real:
    hash x.blsValue.exportRaw()
  else:
    hash x.blob

template hash*(x: BlsCurveType): Hash =
  # TODO: prevent using secret keys
  bind getBytes
  hash(getBytes(x))

# Serialization
# ----------------------------------------------------------------------

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

proc writeValue*(writer: var JsonWriter, value: PublicKey) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var PublicKey) {.inline.} =
  let hex = reader.readValue(string)
  let ok = value.fromHex(hex)
  doAssert ok, "Invalid public key: " & hex

proc writeValue*(writer: var JsonWriter, value: Signature) {.inline.} =
  writer.writeValue($value)

proc readValue*(reader: var JsonReader, value: var Signature) {.inline.} =
  let hex = reader.readValue(string)
  let ok = value.fromHex(hex)
  doAssert ok, "Invalid signature: " & hex

template fromSszBytes*(T: type BlsValue, bytes: openarray[byte]): auto =
  fromBytes(T, bytes)

# Initialization
# ----------------------------------------------------------------------

# For confutils
func init*(T: typedesc[ValidatorPrivKey], hex: string): T {.inline.} =
  let success = result.fromHex(hex)
  doAssert success, "Private key is invalid" # Don't display private keys even if invalid

# For mainchain monitor
func init*(T: typedesc[ValidatorPubKey], data: array[48, byte]): T {.inline.} =
  let success = result.fromBytes(data)
  doAssert success, "Public key is invalid" # Don't display private keys even if invalid
