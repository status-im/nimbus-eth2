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
  RawPrivKeySize* = 48

type
  BlsValueKind* = enum
    ToBeChecked
    Real
    InvalidBLS
    OpaqueBlob # For SSZ testing only

  BlsValue*[N: static int, T: blscurve.PublicKey or blscurve.Signature] = object
    ## This is a lazily initiated wrapper for the underlying cryptographic type
    ##
    ## Fields intentionally private to avoid displaying/logging the raw data
    ## or accessing fields without promoting them
    ## or trying to iterate on a case object even though the case is wrong.
    ## Is there a way to prevent macro from doing that? (SSZ/Chronicles)
    #
    # Note, since 0.20 case object transition are very restrictive
    # and do not allow to preserve content (https://github.com/nim-lang/RFCs/issues/56)
    # Fortunately, the content is transformed anyway if the object is valid
    # but we might want to keep the invalid content at least for logging before discarding it.
    # Our usage requires "-d:nimOldCaseObjects"
    case kind: BlsValueKind
    of Real:
      blsValue: T
    of ToBeChecked, InvalidBLS, OpaqueBlob:
      blob: array[N, byte]

  ValidatorPubKey* = BlsValue[RawPubKeySize, blscurve.PublicKey]

  ValidatorPrivKey* = distinct blscurve.SecretKey

  ValidatorSig* = BlsValue[RawSigSize, blscurve.Signature]

  BlsCurveType* = ValidatorPrivKey | ValidatorPubKey | ValidatorSig

  BlsResult*[T] = Result[T, cstring]

  RandomSourceDepleted* = object of CatchableError

  TrustedSig* = object
    data*: array[RawSigSize, byte]

  SomeSig* = TrustedSig | ValidatorSig

# Lazy parsing
# ----------------------------------------------------------------------

func unsafePromote*[N, T](a: ptr BlsValue[N, T]) =
  ## Try promoting an opaque blob to its corresponding
  ## BLS value.
  ##
  ## ⚠️ Warning - unsafe.
  ## At a low-level we mutate the input but all API like
  ## bls_sign, bls_verify assume that their inputs are immutable
  if a.kind != ToBeChecked:
    return

  # Try if valid BLS value
  var buffer: T
  let success = buffer.fromBytes(a.blob)

  # Unsafe hidden mutation of the input
  if true:
    a.kind = Real # Requires "-d:nimOldCaseObjects"
    a.blsValue = buffer
  else:
    a.kind = InvalidBLS

# Accessors
# ----------------------------------------------------------------------

func setBlob*[N, T](a: var BlsValue[N, T], data: array[N, byte]) {.inline.} =
  ## Set a BLS Value lazily
  a.blob = data

func keyGen*(ikm: openArray[byte]): BlsResult[tuple[pub: ValidatorPubKey, priv: ValidatorPrivKey]] {.inline.} =
  ## Key generation using the BLS Signature draft 2 (https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-02)
  ## Note: As of July-2020, the only use-case is for testing
  ##
  ## Validator key generation should use Lamport Signatures (EIP-2333)
  ## (https://eips.ethereum.org/EIPS/eip-2333)
  ## and be done in a dedicated hardened module/process.
  var
    sk: SecretKey
    pk: PublicKey
  if keyGen(ikm, pk, sk):
    ok((ValidatorPubKey(kind: Real, blsValue: pk), ValidatorPrivKey(sk)))
  else:
    err "bls: cannot generate keypair"

# Comparison
# ----------------------------------------------------------------------

func `==`*(a, b: BlsValue): bool =
  unsafePromote(a.unsafeAddr)
  unsafePromote(b.unsafeAddr)
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

func aggregate*(x: var ValidatorSig, other: ValidatorSig) =
  ## Aggregate 2 Validator Signatures
  ## This assumes that they are real signatures
  ## and will crash if they are not
  unsafePromote(x.addr)
  unsafePromote(other.unsafeAddr)
  x.blsValue.aggregate(other.blsValue)

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#bls-signatures
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
  unsafePromote(pubkey.unsafeAddr)
  unsafePromote(signature.unsafeAddr)

  if signature.kind != Real:
    # InvalidBLS signatures are possible in deposits (discussed with Danny)
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

func blsSign*(privkey: ValidatorPrivKey, message: openArray[byte]): ValidatorSig =
  ## Computes a signature from a secret key and a message
  ValidatorSig(kind: Real, blsValue: SecretKey(privkey).sign(message))

func blsFastAggregateVerify*(
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
  unsafePromote(signature.unsafeAddr)
  if signature.kind != Real:
    return false
  var unwrapped: seq[PublicKey]
  for i in 0 ..< publicKeys.len:
    unsafePromote(publicKeys[i].unsafeAddr)
    if publicKeys[i].kind != Real:
      return false
    unwrapped.add publicKeys[i].blsValue

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

func toRaw*(x: ValidatorPrivKey): array[RawPrivKeySize, byte] =
  # TODO: distinct type - see https://github.com/status-im/nim-blscurve/pull/67
  SecretKey(x).exportRaw()

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
  when defined(ssz_testing):
    # Only for SSZ parsing tests, everything is an opaque blob
    ok BT(kind: OpaqueBlob, blob: toArray(N, bytes))
  else:
    # Lazily instantiate the value, it will be checked only on use
    # TODO BlsResult is now unnecessary
    ok BT(kind: ToBeChecked, blob: toArray(N, bytes))

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

chronicles.formatIt BlsValue: it.shortLog
chronicles.formatIt ValidatorPrivKey: it.shortLog
chronicles.formatIt TrustedSig: it.shortLog

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
