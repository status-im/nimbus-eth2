# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
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

{.push raises: [Defect].}

import
  # Standard library
  options, tables,
  # Internal
  ./digest,
  # Status
  stew/[endians2, objects, results, byteutils],
  blscurve,
  chronicles,
  json_serialization,
  # Standard library
  hashes

export results, json_serialization

# Type definitions
# ----------------------------------------------------------------------

const
  RawSigSize* = 96
  RawPubKeySize* = 48
  # RawPrivKeySize* = 48 for Miracl / 32 for BLST

type
  BlsValueType* = enum
    Real
    OpaqueBlob

  BlsValue*[N: static int, T: blscurve.PublicKey or blscurve.Signature] = object
    # TODO This is a temporary type needed until we sort out the
    # issues with invalid BLS values appearing in the SSZ test suites.
    case kind*: BlsValueType
    of Real:
      blsValue*: T
    of OpaqueBlob:
      blob*: array[N, byte]

  ValidatorPubKey* = BlsValue[RawPubKeySize, blscurve.PublicKey]

  ValidatorPrivKey* = distinct blscurve.SecretKey

  ValidatorSig* = BlsValue[RawSigSize, blscurve.Signature]

  BlsCurveType* = ValidatorPrivKey | ValidatorPubKey | ValidatorSig

  BlsResult*[T] = Result[T, cstring]

  RandomSourceDepleted* = object of CatchableError

  TrustedSig* = object
    data*: array[RawSigSize, byte]

  SomeSig* = TrustedSig | ValidatorSig

export AggregateSignature

func `==`*(a, b: BlsValue): bool =
  if a.kind != b.kind: return false
  if a.kind == Real:
    return a.blsValue == b.blsValue
  else:
    return a.blob == b.blob

template `==`*[N, T](a: BlsValue[N, T], b: T): bool =
  a.blsValue == b

template `==`*[N, T](a: T, b: BlsValue[N, T]): bool =
  a == b.blsValue

# API
# ----------------------------------------------------------------------
# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#bls-signatures

func toPubKey*(privkey: ValidatorPrivKey): ValidatorPubKey =
  ## Create a private key from a public key
  # Un-specced in either hash-to-curve or Eth2
  # TODO: Test suite should use `keyGen` instead
  ValidatorPubKey(kind: Real, blsValue: SecretKey(privkey).privToPub())

proc toRealPubKey(pubkey: ValidatorPubKey): Option[ValidatorPubKey] =
  var validatorKeyCache {.threadvar.}:
    Table[array[RawPubKeySize, byte], Option[ValidatorPubKey]]

  case pubkey.kind:
  of Real:
    return some(pubkey)
  of OpaqueBlob:
    validatorKeyCache.withValue(pubkey.blob, key) do:
      return key[]
    do:
      var val: blscurve.PublicKey
      let maybeRealKey =
        if fromBytes(val, pubkey.blob):
          some ValidatorPubKey(kind: Real, blsValue: val)
        else:
          none ValidatorPubKey
      return validatorKeyCache.mGetOrPut(pubkey.blob, maybeRealKey)

proc initPubKey*(pubkey: ValidatorPubKey): ValidatorPubKey =
  let key = toRealPubKey(pubkey)
  if key.isNone:
    return ValidatorPubKey()
  key.get

func init*(agg: var AggregateSignature, sig: ValidatorSig) {.inline.}=
  ## Initializes an aggregate signature context
  ## This assumes that the signature is valid
  agg.init(sig.blsValue)

func aggregate*(agg: var AggregateSignature, sig: ValidatorSig) {.inline.}=
  ## Aggregate two Validator Signatures
  ## This assumes that they are real signatures
  agg.aggregate(sig.blsValue)

func finish*(agg: AggregateSignature): ValidatorSig {.inline.}=
  ## Canonicalize an AggregateSignature into a signature
  result.kind = Real
  result.blsValue.finish(agg)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#bls-signatures
proc blsVerify*(
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
  let realkey = toRealPubKey(pubkey)
  if realkey.isNone:
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
  realkey.get.blsValue.verify(message, signature.blsValue)

func blsSign*(privkey: ValidatorPrivKey, message: openArray[byte]): ValidatorSig =
  ## Computes a signature from a secret key and a message
  ValidatorSig(kind: Real, blsValue: SecretKey(privkey).sign(message))

proc blsFastAggregateVerify*(
       publicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
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
    let realkey = toRealPubKey(pubkey)
    if realkey.isNone:
      return false
    unwrapped.add realkey.get.blsValue

  fastAggregateVerify(unwrapped, message, signature.blsValue)

proc toGaugeValue*(hash: Eth2Digest): int64 =
  # Only the last 8 bytes are taken into consideration in accordance
  # to the ETH2 metrics spec:
  # https://github.com/ethereum/eth2.0-metrics/blob/6a79914cb31f7d54858c7dd57eee75b6162ec737/metrics.md#interop-metrics
  cast[int64](uint64.fromBytesLE(hash.data[24..31]))

# Codecs
# ----------------------------------------------------------------------

func `$`*(x: ValidatorPrivKey): string =
  "<private key>"

func `$`*(x: BlsValue): string =
  # The prefix must be short
  # due to the mechanics of the `shortLog` function.
  if x.kind == Real:
    x.blsValue.toHex()
  else:
    "raw: " & x.blob.toHex()

func toRaw*(x: ValidatorPrivKey): array[32, byte] =
  # TODO: distinct type - see https://github.com/status-im/nim-blscurve/pull/67
  when BLS_BACKEND == "blst" or (
    BLS_BACKEND == "auto" and (defined(arm64) or defined(amd64))
  ):
    result = SecretKey(x).exportRaw()
  else:
    # Miracl exports to 384-bit arrays, but Curve order is 256-bit
    let raw = SecretKey(x).exportRaw()
    result[0..32-1] = raw.toOpenArray(48-32, 48-1)

func toRaw*(x: BlsValue): auto =
  if x.kind == Real:
    x.blsValue.exportRaw()
  else:
    x.blob

func toRaw*(x: TrustedSig): auto =
  x.data

func toHex*(x: BlsCurveType): string =
  toHex(toRaw(x))

func fromRaw*(T: type ValidatorPrivKey, bytes: openArray[byte]): BlsResult[T] =
  var val: SecretKey
  if val.fromBytes(bytes):
    ok ValidatorPrivKey(val)
  else:
    err "bls: invalid private key"

func fromRaw*[N, T](BT: type BlsValue[N, T], bytes: openArray[byte]): BlsResult[BT] =
  # This is a workaround, so that we can deserialize the serialization of a
  # default-initialized BlsValue without raising an exception
  when defined(ssz_testing) or BT is ValidatorPubKey:
    ok BT(kind: OpaqueBlob, blob: toArray(N, bytes))
  else:
    # Try if valid BLS value
    var val: T
    if fromBytes(val, bytes):
      ok BT(kind: Real, blsValue: val)
    else:
      ok BT(kind: OpaqueBlob, blob: toArray(N, bytes))

func fromHex*(T: type BlsCurveType, hexStr: string): BlsResult[T] {.inline.} =
  ## Initialize a BLSValue from its hex representation
  try:
    T.fromRaw(hexStr.hexToSeqByte())
  except ValueError:
    err "bls: cannot parse value"

# Hashing
# ----------------------------------------------------------------------

template hash*(x: BlsCurveType): Hash =
  # TODO: prevent using secret keys
  bind toRaw
  hash(toRaw(x))

# Serialization
# ----------------------------------------------------------------------

{.pragma: serializationRaises, raises: [SerializationError, IOError, Defect].}

proc writeValue*(writer: var JsonWriter, value: ValidatorPubKey) {.
    inline, raises: [IOError, Defect].} =
  writer.writeValue(value.toHex())

proc readValue*(reader: var JsonReader, value: var ValidatorPubKey)
               {.serializationRaises.} =
  let key = ValidatorPubKey.fromHex(reader.readValue(string))
  if key.isOk:
    value = key.get
  else:
    # TODO: Can we provide better diagnostic?
    raiseUnexpectedValue(reader, "Valid hex-encoded public key expected")

proc writeValue*(writer: var JsonWriter, value: ValidatorSig) {.
    inline, raises: [IOError, Defect].} =
  # Workaround: https://github.com/status-im/nim-beacon-chain/issues/374
  writer.writeValue(value.toHex())

proc readValue*(reader: var JsonReader, value: var ValidatorSig)
               {.serializationRaises.} =
  let sig = ValidatorSig.fromHex(reader.readValue(string))
  if sig.isOk:
    value = sig.get
  else:
    # TODO: Can we provide better diagnostic?
    raiseUnexpectedValue(reader, "Valid hex-encoded signature expected")

proc writeValue*(writer: var JsonWriter, value: ValidatorPrivKey) {.
    inline, raises: [IOError, Defect].} =
  writer.writeValue(value.toHex())

proc readValue*(reader: var JsonReader, value: var ValidatorPrivKey)
               {.serializationRaises.} =
  let key = ValidatorPrivKey.fromHex(reader.readValue(string))
  if key.isOk:
    value = key.get
  else:
    # TODO: Can we provide better diagnostic?
    raiseUnexpectedValue(reader, "Valid hex-encoded private key expected")

template fromSszBytes*(T: type BlsValue, bytes: openArray[byte]): auto =
  let v = fromRaw(T, bytes)
  if v.isErr:
    raise newException(MalformedSszError, $v.error)
  v[]

# Logging
# ----------------------------------------------------------------------

func shortLog*(x: BlsValue): string =
  ## Logging for wrapped BLS types
  ## that may contain valid or non-validated data
  # The prefix must be short
  # due to the mechanics of the `shortLog` function.
  if x.kind == Real:
    x.blsValue.exportRaw()[0..3].toHex()
  else:
    "raw: " & x.blob[0..3].toHex()

func shortLog*(x: ValidatorPrivKey): string =
  ## Logging for raw unwrapped BLS types
  "<private key>"

func shortLog*(x: TrustedSig): string =
  x.data[0..3].toHex()

# Initialization
# ----------------------------------------------------------------------

# TODO more specific exceptions? don't raise?

# For confutils
func init*(T: typedesc[ValidatorPrivKey], hex: string): T {.noInit, raises: [ValueError, Defect].} =
  let v = T.fromHex(hex)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]


# For mainchain monitor
func init*(T: typedesc[ValidatorPubKey], data: array[RawPubKeySize, byte]): T {.noInit, raises: [ValueError, Defect].} =
  let v = T.fromRaw(data)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

# For mainchain monitor
func init*(T: typedesc[ValidatorSig], data: array[RawSigSize, byte]): T {.noInit, raises: [ValueError, Defect].} =
  let v = T.fromRaw(data)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

proc burnMem*(key: var ValidatorPrivKey) =
  key = default(ValidatorPrivKey)
