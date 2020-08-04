import
  # Standard library
  tables, json,

  # Nimble packages
  stew/byteutils, ssz/types,
  json_rpc/jsonmarshal,

  # Local modules
  spec/[datatypes, crypto]

proc fromJson*(n: JsonNode, argName: string, result: var ValidatorPubKey) =
  n.kind.expect(JString, argName)
  result = ValidatorPubKey.fromHex(n.getStr()).tryGet()

proc `%`*(pubkey: ValidatorPubKey): JsonNode =
  unsafePromote(pubkey.unsafeAddr)
  result = newJString($pubkey)

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
  unsafePromote(value.unsafeAddr)
  result = newJString($value)

proc fromJson*(n: JsonNode, argName: string, result: var Version) =
  n.kind.expect(JString, argName)
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

template `%`*(value: GraffitiBytes): JsonNode =
  %($value)

proc fromJson*(n: JsonNode, argName: string, value: var GraffitiBytes) =
  n.kind.expect(JString, argName)
  value = GraffitiBytes.init n.getStr()

proc `%`*(value: CommitteeIndex): JsonNode =
  result = newJInt(value.int)
