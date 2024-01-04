# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
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

{.push raises: [].}

import
  # Status
  stew/[bitseqs, endians2, objects, results, byteutils],
  blscurve,
  chronicles,
  bearssl/rand,
  json_serialization

from std/hashes import Hash
from std/sequtils import mapIt
from std/tables import Table, withValue, `[]=`

from nimcrypto/utils import burnMem

export results, blscurve, rand, json_serialization

# Type definitions
# ----------------------------------------------------------------------

const
  RawSigSize* = 96
  RawPubKeySize* = 48
  UncompressedPubKeySize* = 96
  # RawPrivKeySize* = 48 for Miracl / 32 for BLST

type
  ValidatorPubKey* = object ##\
    ## Compressed raw serialized key bytes - this type is used in so as to not
    ## eagerly load keys - deserialization is slow, as are equality checks -
    ## however, it is not guaranteed that the key is valid (except in some
    ## cases, like the database state)
    ##
    ## It must be 8-byte aligned because `hash(ValidatorPubKey)` just casts a
    ## ptr to one to a ptr to the other, so it needs a compatible alignment.
    blob* {.align: 16.}: array[RawPubKeySize, byte]

  UncompressedPubKey* = object
    ## Uncompressed variation of ValidatorPubKey - this type is faster to
    ## deserialize but doubles the storage footprint
    blob* {.align: 16.}: array[UncompressedPubKeySize, byte]

  CookedPubKey* = distinct blscurve.PublicKey ## Valid deserialized key

  ValidatorSig* = object
    blob* {.align: 16.}: array[RawSigSize, byte]

  ValidatorPrivKey* = distinct blscurve.SecretKey

  BlsCurveType* = ValidatorPrivKey | ValidatorPubKey | ValidatorSig

  BlsResult*[T] = Result[T, cstring]

  TrustedSig* = object
    data* {.align: 16.}: array[RawSigSize, byte]

  SomeSig* = TrustedSig | ValidatorSig

  CookedSig* = distinct blscurve.Signature  ## \
    ## Cooked signatures are those that have been loaded successfully from a
    ## ValidatorSig and are used to avoid expensive reloading as well as error
    ## checking

  SignatureShare* = object
    sign*: blscurve.Signature
    id*: uint32

  SecretShare* = object
    key*: ValidatorPrivKey
    id*: uint32

export
  AggregateSignature

# API
# ----------------------------------------------------------------------
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#bls-signatures

func toPubKey*(privkey: ValidatorPrivKey): CookedPubKey =
  ## Derive a public key from a private key
  # Un-specced in either hash-to-curve or Eth2
  var pubKey: blscurve.PublicKey
  let ok = publicFromSecret(pubKey, SecretKey privkey)
  doAssert ok, "The validator private key was a zero key. This should never happen."

  CookedPubKey(pubKey)

template toRaw*(x: CookedPubKey): auto =
  PublicKey(x).exportRaw()

template toUncompressed*(x: CookedPubKey): auto =
  UncompressedPubKey(blob: PublicKey(x).exportUncompressed())

func toPubKey*(pubKey: CookedPubKey): ValidatorPubKey =
  ## Derive a public key from a private key
  # Un-specced in either hash-to-curve or Eth2
  ValidatorPubKey(blob: pubKey.toRaw())

func load*(v: ValidatorPubKey): Opt[CookedPubKey] =
  ## Parse signature blob - this may fail
  var val: blscurve.PublicKey
  if fromBytes(val, v.blob):
    Opt.some CookedPubKey(val)
  else:
    Opt.none CookedPubKey

func load*(v: UncompressedPubKey): Opt[CookedPubKey] =
  ## Parse signature blob - this may fail
  var val: blscurve.PublicKey
  if fromBytes(val, v.blob):
    Opt.some CookedPubKey(val)
  else:
    Opt.none CookedPubKey

func loadValid*(v: UncompressedPubKey | ValidatorPubKey): CookedPubKey {.noinit.} =
  ## Parse known-to-be-valid key - this is the case for any key that's passed
  ## parsing once and is the output of serialization, such as those keys we
  ## keep in the database or state.
  var val: blscurve.PublicKey
  let ok = fromBytesKnownOnCurve(val, v.blob)
  doAssert ok, "Valid key no longer parses, data corrupt? " & $v

  CookedPubKey(val)

proc loadWithCache*(v: ValidatorPubKey): Opt[CookedPubKey] =
  ## Parse public key blob - this may fail - this function uses a cache to
  ## avoid the expensive deserialization - for now, external public keys only
  ## come from deposits in blocks - when more sources are added, the memory
  ## usage of the cache should be considered
  var cache {.threadvar.}: Table[typeof(v.blob), CookedPubKey]

  # Try to get parse value from cache - if it's not in there, try to parse it -
  # if that's not possible, it's broken
  cache.withValue(v.blob, key) do:
    return Opt.some key[]
  do:
    # Only valid keys are cached
    let cooked = v.load()
    if cooked.isSome():
      cache[v.blob] = cooked.get()
    return cooked

func load*(v: ValidatorSig): Opt[CookedSig] =
  ## Parse signature blob - this may fail
  var parsed: blscurve.Signature
  if fromBytes(parsed, v.blob):
    Opt.some(CookedSig(parsed))
  else:
    Opt.none(CookedSig)

func init*(agg: var AggregatePublicKey, pubkey: CookedPubKey) {.inline.}=
  ## Initializes an aggregate signature context
  agg.init(blscurve.PublicKey(pubkey))

func init*(T: type AggregatePublicKey, pubkey: CookedPubKey): T =
  result.init(pubkey)

func aggregate*(agg: var AggregatePublicKey, pubkey: CookedPubKey) {.inline.}=
  ## Aggregate two valid Validator Public Keys
  agg.aggregate(blscurve.PublicKey(pubkey))

func finish*(agg: AggregatePublicKey): CookedPubKey {.inline.} =
  ## Canonicalize an AggregatePublicKey into a signature
  var pubkey: blscurve.PublicKey
  pubkey.finish(agg)
  CookedPubKey(pubkey)

func init*(agg: var AggregateSignature, sig: CookedSig) {.inline.}=
  ## Initializes an aggregate signature context
  agg.init(blscurve.Signature(sig))

func init*(T: type AggregateSignature, sig: CookedSig): T =
  result.init(sig)

func aggregate*(agg: var AggregateSignature, sig: CookedSig) {.inline.}=
  ## Aggregate two valid Validator Signatures
  agg.aggregate(blscurve.Signature(sig))

func finish*(agg: AggregateSignature): CookedSig {.inline.} =
  ## Canonicalize an AggregateSignature into a signature
  var sig: blscurve.Signature
  sig.finish(agg)
  CookedSig(sig)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#bls-signatures
func blsVerify*(
    pubkey: CookedPubKey, message: openArray[byte],
    signature: CookedSig): bool =
  ## Check that a signature is valid for a message
  ## under the provided public key.
  ## returns `true` if the signature is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  PublicKey(pubkey).verify(message, blscurve.Signature(signature))

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/beacon-chain.md#bls-signatures
proc blsVerify*(
    pubkey: ValidatorPubKey, message: openArray[byte],
    signature: CookedSig): bool =
  ## Check that a signature is valid for a message
  ## under the provided public key.
  ## returns `true` if the signature and the pubkey is valid, `false` otherwise.
  ##
  ## The proof-of-possession MUST be verified before calling this function.
  ## It is recommended to use the overload that accepts a proof-of-possession
  ## to enforce correct usage.
  let
    parsedKey = pubkey.loadWithCache()

  # Guard against invalid signature blobs that fail to parse
  parsedKey.isSome() and blsVerify(parsedKey.get(), message, signature)

proc blsVerify*(
    pubkey: ValidatorPubKey | CookedPubKey, message: openArray[byte],
    signature: ValidatorSig): bool =
  let
    parsedSig = signature.load()
  # Guard against invalid signature blobs that fail to parse
  parsedSig.isSome() and blsVerify(pubkey, message, parsedSig.get())

func blsVerify*(sigSet: SignatureSet): bool =
  ## Unbatched verification
  ## of 1 SignatureSet
  ## tuple[pubkey: blscurve.PublicKey, message: array[32, byte], blscurve.signature: Signature]
  verify(
    sigSet.pubkey,
    sigSet.message,
    sigSet.signature
  )

func blsSign*(privkey: ValidatorPrivKey, message: openArray[byte]): CookedSig =
  ## Computes a signature from a secret key and a message
  CookedSig(SecretKey(privkey).sign(message))

func blsFastAggregateVerify*(
       publicKeys: openArray[CookedPubKey],
       message: openArray[byte],
       signature: CookedSig
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
  let keys = mapIt(publicKeys, PublicKey(it))
  fastAggregateVerify(keys, message, blscurve.Signature(signature))

proc blsFastAggregateVerify*(
       publicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: CookedSig
     ): bool =
  var unwrapped: seq[PublicKey]
  for pubkey in publicKeys:
    let realkey = pubkey.loadWithCache()
    if realkey.isNone:
      return false
    unwrapped.add PublicKey(realkey.get)

  fastAggregateVerify(unwrapped, message, blscurve.Signature(signature))

func blsFastAggregateVerify*(
       publicKeys: openArray[CookedPubKey],
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  let parsedSig = signature.load()
  parsedSig.isSome and blsFastAggregateVerify(publicKeys, message, parsedSig.get())

proc blsFastAggregateVerify*(
       publicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  let parsedSig = signature.load()
  parsedSig.isSome and blsFastAggregateVerify(publicKeys, message, parsedSig.get())

proc blsFastAggregateVerify*(
       fullParticipationAggregatePublicKey: ValidatorPubKey,
       nonParticipatingPublicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: CookedSig
     ): bool =
  let unwrappedFull = fullParticipationAggregatePublicKey.loadWithCache.valueOr:
    return false

  var unwrapped = newSeqOfCap[PublicKey](nonParticipatingPublicKeys.len)
  for pubkey in nonParticipatingPublicKeys:
    let realkey = pubkey.loadWithCache.valueOr:
      return false
    unwrapped.add PublicKey(realkey)

  fastAggregateVerify(
    PublicKey(unwrappedFull), unwrapped,
    message, blscurve.Signature(signature))

proc blsFastAggregateVerify*(
       fullParticipationAggregatePublicKey: ValidatorPubKey,
       nonParticipatingPublicKeys: openArray[ValidatorPubKey],
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  let parsedSig = signature.load()
  parsedSig.isSome and blsFastAggregateVerify(
    fullParticipationAggregatePublicKey, nonParticipatingPublicKeys,
    message, parsedSig.get())

proc blsFastAggregateVerify*(
       allPublicKeys: openArray[ValidatorPubKey],
       fullParticipationAggregatePublicKey: ValidatorPubKey,
       participantBits: BitArray,
       message: openArray[byte],
       signature: ValidatorSig
     ): bool =
  const maxParticipants = participantBits.bits
  var numParticipants = 0
  for idx in 0 ..< maxParticipants:
    if participantBits[idx]:
      inc numParticipants

  return
    if numParticipants < 1:
      false
    elif numParticipants > maxParticipants div 2:
      var nonParticipatingPublicKeys = newSeqOfCap[ValidatorPubKey](
        maxParticipants - numParticipants)
      for idx, pubkey in allPublicKeys:
        if not participantBits[idx]:
          nonParticipatingPublicKeys.add pubkey
      blsFastAggregateVerify(
        fullParticipationAggregatePublicKey, nonParticipatingPublicKeys,
        message, signature)
    else:
      var publicKeys = newSeqOfCap[ValidatorPubKey](numParticipants)
      for idx, pubkey in allPublicKeys:
        if participantBits[idx]:
          publicKeys.add pubkey
      blsFastAggregateVerify(publicKeys, message, signature)

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

func toHex*(x: CookedPubKey): string =
  toHex(x.toPubKey())

func `$`*(x: CookedPubKey): string =
  $(x.toPubKey())

func toValidatorSig*(x: CookedSig): ValidatorSig =
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

func `==`*(a, b: ValidatorPrivKey): bool {.error: "Secret keys should stay secret".}

# Hashing
# ----------------------------------------------------------------------

template hash*(x: ValidatorPubKey | ValidatorSig): Hash =
  static: doAssert sizeof(Hash) <= x.blob.len div 2
  # We use rough "middle" of blob for the hash, assuming this is where most of
  # the entropy is found
  cast[ptr Hash](unsafeAddr x.blob[x.blob.len div 2])[]

# Comparison/Sorting
# ----------------------------------------------------------------------

template `<`*(x, y: ValidatorPubKey): bool =
  x.blob < y.blob

# Serialization
# ----------------------------------------------------------------------

{.pragma: serializationRaises, raises: [SerializationError, IOError].}

proc writeValue*(
    writer: var JsonWriter, value: ValidatorPubKey | CookedPubKey
) {.inline, raises: [IOError].} =
  writer.writeValue(value.toHex())

proc readValue*(reader: var JsonReader, value: var ValidatorPubKey)
               {.serializationRaises.} =
  let key = ValidatorPubKey.fromHex(reader.readValue(string))
  if key.isOk:
    value = key.get
  else:
    # TODO: Can we provide better diagnostic?
    raiseUnexpectedValue(reader, "Valid hex-encoded public key expected")

proc writeValue*(
    writer: var JsonWriter, value: ValidatorSig
) {.inline, raises: [IOError].} =
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

proc writeValue*(
    writer: var JsonWriter, value: ValidatorPrivKey
) {.inline, raises: [IOError].} =
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

func shortLog*(x: CookedPubKey): string =
  let raw = x.toRaw()
  byteutils.toHex(raw.toOpenArray(0, 3))

func shortLog*(x: ValidatorPrivKey): string =
  ## Logging for raw unwrapped BLS types
  "<private key>"

func shortLog*(x: TrustedSig): string =
  byteutils.toHex(x.data.toOpenArray(0, 3))

# Initialization
# ----------------------------------------------------------------------

# TODO more specific exceptions? don't raise?

# For confutils
func init*(T: typedesc[ValidatorPrivKey], hex: string): T {.noinit, raises: [ValueError].} =
  let v = T.fromHex(hex)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

# For mainchain monitor
func init*(T: typedesc[ValidatorPubKey], data: array[RawPubKeySize, byte]): T {.noinit, raises: [ValueError].} =
  let v = T.fromRaw(data)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

# For mainchain monitor
func init*(T: typedesc[ValidatorSig], data: array[RawSigSize, byte]): T {.noinit, raises: [ValueError].} =
  let v = T.fromRaw(data)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

func infinity*(T: type ValidatorSig): T =
  result.blob[0] = byte 0xC0

func burnMem*(key: var ValidatorPrivKey) =
  burnMem(addr key, sizeof(ValidatorPrivKey))

{.push warning[ProveField]:off.}  # https://github.com/nim-lang/Nim/issues/22060
proc keyGen(rng: var HmacDrbgContext): BlsResult[blscurve.SecretKey] =
  var
    pubkey: blscurve.PublicKey
  let bytes = rng.generate(array[32, byte])
  result.ok default(blscurve.SecretKey)
  if not keyGen(bytes, pubkey, result.value):
    return err "key generation failed"
{.pop.}

proc secretShareId(x: uint32) : blscurve.ID =
  let bytes: array[8, uint32] = [uint32 x, 0, 0, 0, 0, 0, 0, 0]
  blscurve.ID.fromUint32(bytes)

func generateSecretShares*(sk: ValidatorPrivKey,
                           rng: var HmacDrbgContext,
                           k: uint32, n: uint32): BlsResult[seq[SecretShare]] =
  doAssert k > 0 and k <= n

  var originPts: seq[blscurve.SecretKey]
  originPts.add(blscurve.SecretKey(sk))
  for i in 1 ..< k:
    originPts.add(? keyGen(rng))

  var shares: seq[SecretShare]
  for i in uint32(0) ..< n:
    let numericShareId = i + 1 # the share id must not be zero
    let blsShareId = secretShareId(numericShareId)
    let secret = genSecretShare(originPts, blsShareId)
    let share = SecretShare(key: ValidatorPrivKey(secret), id: numericShareId)
    shares.add(share)

  return ok shares

func toSignatureShare*(sig: CookedSig, id: uint32): SignatureShare =
  result.sign = blscurve.Signature(sig)
  result.id = id

func recoverSignature*(sings: seq[SignatureShare]): CookedSig =
  let signs = sings.mapIt(it.sign)
  let ids = sings.mapIt(secretShareId(it.id))
  CookedSig blscurve.recover(signs, ids).expect(
    "valid shares (validated when loading the keystore)")

proc confirmShares*(pubKey: ValidatorPubKey,
                    shares: seq[SecretShare],
                    rng: var HmacDrbgContext): bool =
  let confirmationData = rng.generate(array[32, byte])
  var signs: seq[SignatureShare]
  for share in items(shares):
    let signature = share.key.blsSign(confirmationData).toSignatureShare(share.id);
    signs.add(signature)
  let recovered = signs.recoverSignature()
  return pubKey.blsVerify(confirmationData, recovered)
