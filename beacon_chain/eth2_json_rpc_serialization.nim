import
  # Standard library
  tables, json,

  # Nimble packages
  stew/byteutils, ssz/types,
  json_rpc/jsonmarshal,

  # Local modules
  spec/[datatypes, crypto]

proc fromJson*(n: JsonNode, argName: string, result: var ValidatorPubKey) =
  result = ValidatorPubKey.fromHex(n.getStr()).tryGet()

proc `%`*(pubkey: ValidatorPubKey): JsonNode =
  result = newJString($pubkey)

proc fromJson*(n: JsonNode, argName: string, result: var List) =
  fromJson(n, argName, asSeq result)

proc `%`*(list: List): JsonNode = %(asSeq(list))

proc fromJson*(n: JsonNode, argName: string, result: var BitList) =
  fromJson(n, argName, seq[byte](BitSeq(result)))

proc `%`*(bitlist: BitList): JsonNode = %(seq[byte](BitSeq(bitlist)))

proc fromJson*(n: JsonNode, argName: string, result: var ValidatorSig) =
  result = ValidatorSig.fromHex(n.getStr()).tryGet()

proc `%`*(value: ValidatorSig): JsonNode =
  result = newJString($value)

proc fromJson*(n: JsonNode, argName: string, result: var Version) =
  hexToByteArray(n.getStr(), array[4, byte](result))

proc `%`*(value: Version): JsonNode =
  result = newJString($value)

template genFromJsonForIntType(t: untyped) =
  proc fromJson*(n: JsonNode, argName: string, result: var t) =
    n.kind.expect(JInt, argName)
    result = n.getInt().t

genFromJsonForIntType(Epoch)
genFromJsonForIntType(Slot)
genFromJsonForIntType(CommitteeIndex)

proc `%`*(value: CommitteeIndex): JsonNode =
  result = newJInt(value.int)
