import
  results,
  stew/byteutils,
  stew/objects,
  blscurve

export blscurve

const
  RawSigSize = 96
  RawPubKeySize* = 48

type
  ValidatorPubKey* = object ##\
    blob {.align: 16.}: array[RawPubKeySize, byte]

  ValidatorSig* = object
    blob {.align: 16.}: array[RawSigSize, byte]

  ValidatorPrivKey = distinct blscurve.SecretKey

  BlsCurveType = ValidatorPrivKey | ValidatorPubKey | ValidatorSig

  BlsResult[T] = Result[T, cstring]

func fromRaw(T: type ValidatorPrivKey, bytes: openArray[byte]): BlsResult[T] =
  var val: SecretKey
  if val.fromBytes(bytes):
    ok ValidatorPrivKey(val)
  else:
    err "bls: invalid private key"

func fromRaw(BT: type[ValidatorPubKey | ValidatorSig], bytes: openArray[byte]): BlsResult[BT] =
  if bytes.len() != sizeof(BT):
    err "bls: invalid bls length"
  else:
    ok BT(blob: toArray(sizeof(BT), bytes))

func fromHex*(T: type BlsCurveType, hexStr: string): BlsResult[T] {.inline.} =
  try:
    T.fromRaw(hexStr.hexToSeqByte())
  except ValueError:
    err "bls: cannot parse value"

func infinity(T: type ValidatorSig): T =
  result.blob[0] = byte 0xC0
