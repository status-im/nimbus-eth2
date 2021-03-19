# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
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
  std/[options, hashes, tables],
  # Internal
  ./digest,
  # Status
  stew/[endians2, objects, results, byteutils],
  blscurve,
  chronicles,
  json_serialization,
  nimcrypto/utils as ncrutils

export results, json_serialization

# Type definitions
# ----------------------------------------------------------------------

const
  RawSigSize* = 96
  RawPubKeySize* = 48
  # RawPrivKeySize* = 48 for Miracl / 32 for BLST

type
  # BLS deserialization is a bit slow, so we deserialize public keys and
  # signatures lazily - this helps operations like comparisons and hashes to
  # be fast (which is important), makes loading blocks and states fast, and
  # allows invalid values in the SSZ byte stream, which is valid from an SSZ
  # point of view - the invalid values are later processed to
  ValidatorPubKey* = object
    blob*: array[RawPubKeySize, byte]

  ValidatorSig* = object
    blob*: array[RawSigSize, byte]

  ValidatorPrivKey* = distinct blscurve.SecretKey

  BlsCurveType* = ValidatorPrivKey | ValidatorPubKey | ValidatorSig

  BlsResult*[T] = Result[T, cstring]

  TrustedSig* = object
    data*: array[RawSigSize, byte]

  SomeSig* = TrustedSig | ValidatorSig

  CookedSig* = distinct blscurve.Signature  ## \
  ## Allows loading in an atttestation or other message's signature once across
  ## all its computations, rather than repeatedly re-loading it each time it is
  ## referenced. This primarily currently serves the attestation pool.

export AggregateSignature

# API
# ----------------------------------------------------------------------
# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#bls-signatures

func toPubKey*(privkey: ValidatorPrivKey): ValidatorPubKey =
  ## Derive a public key from a private key
  # Un-specced in either hash-to-curve or Eth2
  var pubKey: blscurve.PublicKey
  let ok = publicFromSecret(pubKey, SecretKey privkey)
  doAssert ok, "The validator private key was a zero key. This should never happen."

  ValidatorPubKey(blob: pubKey.exportRaw())

proc loadWithCache*(v: ValidatorPubKey): Option[blscurve.PublicKey] =
  ## Parse public key blob - this may fail - this function uses a cache to
  ## avoid the expensive deserialization - for now, external public keys only
  ## come from deposits in blocks - when more sources are added, the memory
  ## usage of the cache should be considered
  var cache {.threadvar.}: Table[typeof(v.blob), blscurve.PublicKey]

  # Try to get parse value from cache - if it's not in there, try to parse it -
  # if that's not possible, it's broken
  cache.withValue(v.blob, key) do:
    return some key[]
  do:
    # Only valid keys are cached
    var val: blscurve.PublicKey
    return
      if fromBytes(val, v.blob):
        some cache.mGetOrPut(v.blob, val)
      else:
        none blscurve.PublicKey

proc load*(v: ValidatorSig): Option[blscurve.Signature] =
  ## Parse signature blob - this may fail
  var parsed: blscurve.Signature
  if fromBytes(parsed, v.blob):
    some(parsed)
  else:
    none(blscurve.Signature)

func init*(agg: var AggregateSignature, sig: ValidatorSig) {.inline.}=
  ## Initializes an aggregate signature context
  ## This assumes that the signature is valid
  agg.init(sig.load().get())

func init*(agg: var AggregateSignature, sig: CookedSig) {.inline.}=
  ## Initializes an aggregate signature context
  agg.init(blscurve.Signature(sig))

proc aggregate*(agg: var AggregateSignature, sig: ValidatorSig) {.inline.}=
  ## Aggregate two Validator Signatures
  ## Both signatures must be valid
  agg.aggregate(sig.load.get())

proc aggregate*(agg: var AggregateSignature, sig: CookedSig) {.inline.}=
  ## Aggregate two Validator Signatures
  agg.aggregate(blscurve.Signature(sig))

func finish*(agg: AggregateSignature): ValidatorSig {.inline.}=
  ## Canonicalize an AggregateSignature into a signature
  var sig: blscurve.Signature
  sig.finish(agg)
  ValidatorSig(blob: sig.exportRaw())

# https://github.com/ethereum/eth2.0-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#bls-signatures
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
  let
    parsedSig = signature.load()

  if parsedSig.isNone():
    false
  else:
    let
      parsedKey = pubkey.loadWithCache()

    # It may happen that signatures or keys fail to parse as invalid blobs may
    # be passed around - for example, the deposit contract doesn't verify
    # signatures, so the loading happens lazily at verification time instead!
    parsedKey.isSome() and
      parsedKey.get.verify(message, parsedSig.get())

proc blsVerify*(sigSet: SignatureSet): bool =
  ## Unbatched verification
  ## of 1 SignatureSet
  ## tuple[pubkey: blscurve.PublicKey, message: array[32, byte], blscurve.signature: Signature]
  verify(
    sigSet.pubkey,
    sigSet.message,
    sigSet.signature
  )

func blsSign*(privkey: ValidatorPrivKey, message: openArray[byte]): ValidatorSig =
  ## Computes a signature from a secret key and a message
  let sig = SecretKey(privkey).sign(message)
  ValidatorSig(blob: sig.exportRaw())

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
  let parsedSig = signature.load()
  if not parsedSig.isSome():
    return false
  var unwrapped: seq[PublicKey]
  for pubkey in publicKeys:
    let realkey = pubkey.loadWithCache()
    if realkey.isNone:
      return false
    unwrapped.add realkey.get

  fastAggregateVerify(unwrapped, message, parsedSig.get())

proc toGaugeValue*(hash: Eth2Digest): int64 =
  # Only the last 8 bytes are taken into consideration in accordance
  # to the ETH2 metrics spec:
  # https://github.com/ethereum/eth2.0-metrics/blob/6a79914cb31f7d54858c7dd57eee75b6162ec737/metrics.md#interop-metrics
  cast[int64](uint64.fromBytesLE(hash.data.toOpenArray(24, 31)))

# Codecs
# ----------------------------------------------------------------------

func `$`*(x: ValidatorPrivKey): string =
  "<private key>"

func `$`*(x: ValidatorPubKey | ValidatorSig): string =
  x.blob.toHex()

func toRaw*(x: ValidatorPrivKey): array[32, byte] =
  # TODO: distinct type - see https://github.com/status-im/nim-blscurve/pull/67
  when BLS_BACKEND == BLST:
    result = SecretKey(x).exportRaw()
  else:
    # Miracl exports to 384-bit arrays, but Curve order is 256-bit
    let raw = SecretKey(x).exportRaw()
    result[0..32-1] = raw.toOpenArray(48-32, 48-1)

template toRaw*(x: ValidatorPubKey | ValidatorSig): auto =
  x.blob

template toRaw*(x: TrustedSig): auto =
  x.data

func toHex*(x: BlsCurveType): string =
  toHex(toRaw(x))

func exportRaw*(x: CookedSig): ValidatorSig =
  ValidatorSig(blob: blscurve.Signature(x).exportRaw())

func fromRaw*(T: type ValidatorPrivKey, bytes: openArray[byte]): BlsResult[T] =
  var val: SecretKey
  if val.fromBytes(bytes):
    ok ValidatorPrivKey(val)
  else:
    err "bls: invalid private key"

func fromRaw*(BT: type[ValidatorPubKey | ValidatorSig], bytes: openArray[byte]): BlsResult[BT] =
  # Signatures and keys are deserialized lazily
  if bytes.len() != sizeof(BT):
    err "bls: invalid bls length"
  else:
    ok BT(blob: toArray(sizeof(BT), bytes))

func fromHex*(T: type BlsCurveType, hexStr: string): BlsResult[T] {.inline.} =
  ## Initialize a BLSValue from its hex representation
  try:
    T.fromRaw(hexStr.hexToSeqByte())
  except ValueError:
    err "bls: cannot parse value"

func `==`*(a, b: ValidatorPubKey | ValidatorSig): bool =
  equalMem(unsafeAddr a.blob[0], unsafeAddr b.blob[0], sizeof(a.blob))

# Hashing
# ----------------------------------------------------------------------

template hash*(x: ValidatorPubKey | ValidatorSig): Hash =
  static: doAssert sizeof(Hash) <= x.blob.len div 2
  # We use rough "middle" of blob for the hash, assuming this is where most of
  # the entropy is found
  cast[ptr Hash](unsafeAddr x.blob[x.blob.len div 2])[]

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
  # Workaround: https://github.com/status-im/nimbus-eth2/issues/374
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

template fromSszBytes*(T: type[ValidatorPubKey | ValidatorSig], bytes: openArray[byte]): auto =
  let v = fromRaw(T, bytes)
  if v.isErr:
    raise newException(MalformedSszError, $v.error)
  v[]

# Logging
# ----------------------------------------------------------------------

func shortLog*(x: ValidatorPubKey | ValidatorSig): string =
  ## Logging for wrapped BLS types
  ## that may contain valid or non-validated data
  byteutils.toHex(x.blob.toOpenArray(0, 3))

func shortLog*(x: ValidatorPrivKey): string =
  ## Logging for raw unwrapped BLS types
  "<private key>"

func shortLog*(x: TrustedSig): string =
  byteutils.toHex(x.data.toOpenArray(0, 3))

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
  ncrutils.burnMem(addr key, sizeof(ValidatorPrivKey))
