import
  # Standard library
  tables, json, parseutils,

  # Nimble packages
  stew/byteutils, ssz/types,
  json_rpc/jsonmarshal,

  # Local modules
  spec/[datatypes, crypto]

proc fromJson*(n: JsonNode, argName: string, result: var ValidatorPubKey) =
  n.kind.expect(JString, argName)
  result = ValidatorPubKey.fromHex(n.getStr()).tryGet().initPubKey()

proc `%`*(pubkey: ValidatorPubKey): JsonNode =
  result = newJString($initPubKey(pubkey))

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
  result = newJString($value)

proc fromJson*(n: JsonNode, argName: string, result: var Version) =
  n.kind.expect(JString, argName)
  hexToByteArray(n.getStr(), array[4, byte](result))

proc `%`*(value: Version): JsonNode =
  result = newJString($value)

template genFromJsonForIntType(T: untyped) =
  proc fromJson*(n: JsonNode, argName: string, result: var T) =
    n.kind.expect(JInt, argName)
    let asInt = n.getBiggestInt()
    # signed -> unsigned conversions are unchecked
    # https://github.com/nim-lang/RFCs/issues/175
    if asInt < 0:
      raise newException(
        ValueError, "JSON-RPC input is an unexpected negative value")
    result = T(asInt)

genFromJsonForIntType(Slot)
genFromJsonForIntType(CommitteeIndex)
genFromJsonForIntType(ValidatorIndex)

proc `%`*(value: Epoch): JsonNode =
  result = newJString($value)

proc fromJson*(n: JsonNode, argName: string, result: var Epoch) =
  n.kind.expect(JString, argName)
  let str = n.getStr()
  var parsed: BiggestUInt
  if parseBiggestUInt(str, parsed) != str.len:
    raise newException(CatchableError, "Not a valid epoch number")
  result = parsed.Epoch

template `%`*(value: GraffitiBytes): JsonNode =
  %($value)

proc fromJson*(n: JsonNode, argName: string, value: var GraffitiBytes) =
  n.kind.expect(JString, argName)
  value = GraffitiBytes.init n.getStr()

proc `%`*(value: CommitteeIndex): JsonNode =
  result = newJInt(value.int)

proc `%`*(value: ValidatorIndex): JsonNode =
  result = newJInt(value.int)
