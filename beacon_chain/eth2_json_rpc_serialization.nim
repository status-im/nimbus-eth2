import
  # Standard library
  std/[tables, json, typetraits],

  # Nimble packages
  stew/byteutils, ssz/types,
  json_rpc/jsonmarshal,

  # Local modules
  spec/[datatypes, crypto, digest]

proc toJsonHex(data: openArray[byte]): string =
  # Per the eth2 API spec, hex arrays are printed with leading 0x
  "0x" & toHex(data)

proc fromJson*(n: JsonNode, argName: string, result: var ValidatorPubKey) =
  n.kind.expect(JString, argName)
  result = initPubKey(ValidatorPubKey.fromHex(n.getStr()).tryGet().initPubKey())

proc `%`*(pubkey: ValidatorPubKey): JsonNode =
  newJString(toJsonHex(toRaw(pubkey)))

proc fromJson*(n: JsonNode, argName: string, result: var List) =
  fromJson(n, argName, asSeq result)

proc `%`*(list: List): JsonNode = %(asSeq(list))

proc fromJson*(n: JsonNode, argName: string, result: var BitList) =
  fromJson(n, argName, seq[byte](BitSeq(result)))

proc `%`*(bitlist: BitList): JsonNode = %(seq[byte](BitSeq(bitlist)))

proc fromJson*(n: JsonNode, argName: string, result: var ValidatorSig) =
  n.kind.expect(JString, argName)
  result = ValidatorSig.fromHex(n.getStr()).tryGet()

proc `%`*(value: ValidatorSig): JsonNode =
  newJString(toJsonHex(toRaw(value)))

proc fromJson*(n: JsonNode, argName: string, result: var Version) =
  n.kind.expect(JString, argName)
  hexToByteArray(n.getStr(), array[4, byte](result))

proc `%`*(value: Version): JsonNode =
  newJString(toJsonHex(distinctBase(value)))

template genFromJsonForIntType(T: untyped) =
  proc fromJson*(n: JsonNode, argName: string, result: var T) =
    n.kind.expect(JInt, argName)
    let asInt = n.getBiggestInt()
    when T is Epoch:
      if asInt == -1:
        # TODO: This is a major hack here. Since the json library
        # cannot handle properly 0xffffffff when serializing and
        # deserializing uint64 values, we detect one known wrong
        # result, appering in most `Validator` records. To fix
        # this issue, we'll have to switch to nim-json-serialization
        # in nim-json-rpc or work towards implementing a fix upstream.
        result = FAR_FUTURE_EPOCH
        return
    if asInt < 0:
      # signed -> unsigned conversions are unchecked
      # https://github.com/nim-lang/RFCs/issues/175
      raise newException(
        ValueError, "JSON-RPC input is an unexpected negative value")
    result = T(asInt)

genFromJsonForIntType(Epoch)
genFromJsonForIntType(Slot)
genFromJsonForIntType(CommitteeIndex)
genFromJsonForIntType(ValidatorIndex)

proc `%`*(value: GraffitiBytes): JsonNode =
  newJString(toJsonHex(distinctBase(value)))

proc fromJson*(n: JsonNode, argName: string, value: var GraffitiBytes) =
  n.kind.expect(JString, argName)
  value = GraffitiBytes.init n.getStr()

proc `%`*(value: CommitteeIndex): JsonNode =
  newJInt(value.BiggestInt)

proc `%`*(value: ValidatorIndex): JsonNode =
  newJInt(value.BiggestInt)

proc `%`*(value: Eth2Digest): JsonNode =
  newJString(toJsonHex(value.data))

proc fromJson*(n: JsonNode, argName: string, result: var Eth2Digest) =
  n.kind.expect(JString, argName)
  hexToByteArray(n.getStr(), result.data)
