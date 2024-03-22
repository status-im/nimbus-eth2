import
  results,
  stew/[bitseqs, endians2, objects, byteutils],
  blscurve

from std/hashes import Hash
from std/tables import Table, withValue, `[]=`

export results, blscurve


const
  RawSigSize* = 96
  RawPubKeySize* = 48
  UncompressedPubKeySize* = 96

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

func toPubKey*(privkey: ValidatorPrivKey): CookedPubKey =
  var pubKey: blscurve.PublicKey
  let ok = publicFromSecret(pubKey, SecretKey privkey)
  doAssert ok, "The validator private key was a zero key. This should never happen."

  CookedPubKey(pubKey)

template toRaw*(x: CookedPubKey): auto =
  PublicKey(x).exportRaw()

template toUncompressed*(x: CookedPubKey): auto =
  UncompressedPubKey(blob: PublicKey(x).exportUncompressed())

func toPubKey*(pubKey: CookedPubKey): ValidatorPubKey =
  ValidatorPubKey(blob: pubKey.toRaw())

func load*(v: ValidatorPubKey): Opt[CookedPubKey] =
  var val: blscurve.PublicKey
  if fromBytes(val, v.blob):
    Opt.some CookedPubKey(val)
  else:
    Opt.none CookedPubKey

func load*(v: UncompressedPubKey): Opt[CookedPubKey] =
  var val: blscurve.PublicKey
  if fromBytes(val, v.blob):
    Opt.some CookedPubKey(val)
  else:
    Opt.none CookedPubKey

func loadValid*(v: UncompressedPubKey | ValidatorPubKey): CookedPubKey {.noinit.} =
  var val: blscurve.PublicKey
  let ok = fromBytesKnownOnCurve(val, v.blob)
  doAssert ok, "Valid key no longer parses, data corrupt? " & $v

  CookedPubKey(val)

proc loadWithCache*(v: ValidatorPubKey): Opt[CookedPubKey] =
  var cache {.threadvar.}: Table[typeof(v.blob), CookedPubKey]

  cache.withValue(v.blob, key) do:
    return Opt.some key[]
  do:
    # Only valid keys are cached
    let cooked = v.load()
    if cooked.isSome():
      cache[v.blob] = cooked.get()
    return cooked

func load*(v: ValidatorSig): Opt[CookedSig] =
  var parsed: blscurve.Signature
  if fromBytes(parsed, v.blob):
    Opt.some(CookedSig(parsed))
  else:
    Opt.none(CookedSig)

func `$`*(x: ValidatorPrivKey): string =
  "<private key>"

func `$`*(x: ValidatorPubKey | ValidatorSig): string =
  x.blob.toHex()

func toRaw*(x: ValidatorPrivKey): array[32, byte] =
  static: doAssert BLS_BACKEND == BLST
  result = SecretKey(x).exportRaw()
  
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
  if bytes.len() != sizeof(BT):
    err "bls: invalid bls length"
  else:
    ok BT(blob: toArray(sizeof(BT), bytes))

func fromHex*(T: type BlsCurveType, hexStr: string): BlsResult[T] {.inline.} =
  try:
    T.fromRaw(hexStr.hexToSeqByte())
  except ValueError:
    err "bls: cannot parse value"

func `==`*(a, b: ValidatorPubKey | ValidatorSig): bool =
  equalMem(unsafeAddr a.blob[0], unsafeAddr b.blob[0], sizeof(a.blob))

func `==`*(a, b: ValidatorPrivKey): bool {.error: "Secret keys should stay secret".}


template hash*(x: ValidatorPubKey | ValidatorSig): Hash =
  static: doAssert sizeof(Hash) <= x.blob.len div 2
  cast[ptr Hash](unsafeAddr x.blob[x.blob.len div 2])[]


template `<`*(x, y: ValidatorPubKey): bool =
  x.blob < y.blob


{.pragma: serializationRaises, raises: [SerializationError, IOError].}

template fromSszBytes*(T: type[ValidatorPubKey | ValidatorSig], bytes: openArray[byte]): auto =
  let v = fromRaw(T, bytes)
  if v.isErr:
    raise newException(MalformedSszError, $v.error)
  v[]


func shortLog*(x: ValidatorPubKey | ValidatorSig): string =
  byteutils.toHex(x.blob.toOpenArray(0, 3))

func shortLog*(x: CookedPubKey): string =
  let raw = x.toRaw()
  byteutils.toHex(raw.toOpenArray(0, 3))

func shortLog*(x: ValidatorPrivKey): string =
  "<private key>"

func shortLog*(x: TrustedSig): string =
  byteutils.toHex(x.data.toOpenArray(0, 3))



func init*(T: typedesc[ValidatorPrivKey], hex: string): T {.noinit, raises: [ValueError].} =
  let v = T.fromHex(hex)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

func init*(T: typedesc[ValidatorPubKey], data: array[RawPubKeySize, byte]): T {.noinit, raises: [ValueError].} =
  let v = T.fromRaw(data)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

func init*(T: typedesc[ValidatorSig], data: array[RawSigSize, byte]): T {.noinit, raises: [ValueError].} =
  let v = T.fromRaw(data)
  if v.isErr:
    raise (ref ValueError)(msg: $v.error)
  v[]

func infinity*(T: type ValidatorSig): T =
  result.blob[0] = byte 0xC0
