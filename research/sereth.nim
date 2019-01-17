import
  json, macros, sequtils, endians,
  eth_common, stint, nimcrypto, byteutils

type
  Validator {.packed.} = object
    # The validator's public key
    pubkey:  Uint256
    # What shard the validator's balance will be sent to
    # after withdrawal
    withdrawal_shard: int16
    # And what address
    withdrawal_address: EthAddress
    # The validator's current RANDAO beacon commitment
    randao_commitment: Hash256
    # Current balance
    balance: int64
    # Dynasty where the validator  is inducted
    start_dynasty: int64
    # Dynasty where the validator leaves
    end_dynasty: int64

macro typeToJson*(T: typedesc): untyped =
  ## Transform a Nim type section in a Json schema
  ## TODO: Add the possibility to force in lexicographical order

  let impl = T.getTypeImpl[1].getTypeImpl               # Access type implementation as a tree
  var typeAsJson: JsonNode = newJObject()
  for field in impl[2]:
    let (fieldName, fieldType) = ($field[0], $field[1]) # convert name and type to string
    typeAsJson[fieldName] = %fieldType                    # % creates a JsonNode from the string that we assign to key = fieldName.
  result = newStrLitNode($typeAsJson)

proc appendBigEndianInt(dst: var seq[byte], src: SomeNumber) =
  ## Append an int as a big-endian int to a sequence of bytes

  const size = sizeof(src)

  proc bigEndian(dst, src: pointer) =
    when size == 2: # int16
      bigEndian16(dst, src)
    elif size == 4: # int32
      bigEndian32(dst, src)
    elif size == 8: # int64
      bigEndian64(dst, src)
    else:
      static: assert false, "src must be a int16, int32 or int64 or unsigned int of the same size"

  dst.setLen(dst.len + size)
  bigEndian(dst[dst.len - size].addr, src.unsafeAddr)

proc serializeETH[T](x: T): seq[byte] =
  ## Serialize an Ethereum type to the PoC serialization format
  const
    magic = "\x7FETHEREUM"
    version = [byte 1, 0]
    schema = typeToJson(T)

  # Write magic string and version
  result = @[]
  for chr in magic:
    result.add byte(chr)
  result.add version

  # Offset of the raw data (stored as int64 even on 32-bit platform):
  #   -  9 bytes of magic header
  #   -  2 bytes for version
  #   -  8 bytes for offset (int64)
  #   - 32 bytes for Blake2 hash for raw data
  #   - ??? bytes for schema
  let
    offset = int64(result.len + sizeof(int64) + sizeof(Hash256) + schema.len)
    metadataStart = result.len + sizeof(int64)

  # Write the offset as a Big Endian int64
  result.setLen(result.len + sizeof(int64))
  bigEndian64(result[result.len - sizeof(int64)].addr, offset.unsafeAddr)

  # Reserve space for Blake2 hash (256-bit / 32 bytes)
  result.setLen(result.len + sizeof(Hash256))

  # Write the schema
  for chr in schema:
    result.add byte(chr)

  assert result.len == offset

  # Write raw data - this is similar to SimpleSerialize
  for field in fields(x):
    when field is UInt256:
      result.add field.toByteArrayBE
    elif field is (int16 or int64):
      result.appendBigEndianInt field
    elif field is EthAddress:
      result.add field
    elif field is Hash256:
      result.add field.data
    else:
      raise newException(ValueError, "Not implemented")

  assert result.len == offset + sizeof(T)

  # Compute the hash
  result[metadataStart ..< metadataStart + sizeof(Hash256)] = blake2_256.digest(result[offset ..< result.len]).data

  # Some reports
  echo "Schema: " & $schema
  echo "Schema size: " & $schema.len
  echo "Raw data offset (== metadata size including schema): " & $offset
  echo "Raw data size (bytes): " & $sizeof(T)
  echo "Total size (bytes): " & $result.len

when isMainModule:
  let x = Validator(
    pubkey: high(Uint256), # 0xFFFF...FFFF
    withdrawal_shard: 4455,
    withdrawal_address: hexToPaddedByteArray[20]("0x1234"),
    randao_commitment: Hash256(data: hexToPaddedByteArray[32]("0xAABBCCDDEEFF")),
    balance: 100000,
    start_dynasty: 1,
    end_dynasty: 2
  )


  let y = serializeETH(x)

  echo "\n##################### \n"
  echo "Byte representation \n"

  # Byte representation
  echo y

  echo "\n##################### \n"
  echo "Char representation \n"

  echo cast[seq[char]](y)

  echo "\n##################### \n"
  echo "Hex representation \n"

  echo byteutils.toHex y

  #################################################################################
  # Output

  # Schema: {"pubkey":"UInt256","withdrawal_shard":"int16","withdrawal_address":"EthAddress","randao_commitment":"Hash256","balance":"int64","start_dynasty":"int64","end_dynasty":"int64"}
  # Schema size: 175
  # Raw data offset (== metadata size including schema): 226
  # Raw data size (bytes): 110
  # Total size (bytes): 336
  #
  # #####################
  #
  # Byte representation
  #
  # @[127, 69, 84, 72, 69, 82, 69, 85, 77, 1, 0, 0, 0, 0, 0, 0, 0, 0, 226, 57, 0, 86, 134, 122, 192, 114, 196, 207, 203, 93, 74, 188, 96, 189, 200, 234, 140, 195, 148, 28, 78, 203, 152, 116, 37, 74, 241, 189, 75, 40, 29, 123, 34, 112, 117, 98, 107, 101, 121, 34, 58, 34, 85, 73, 110, 116, 50, 53, 54, 34, 44, 34, 119, 105, 116, 104, 100, 114, 97, 119, 97, 108, 95, 115, 104, 97, 114, 100, 34, 58, 34, 105, 110, 116, 49, 54, 34, 44, 34, 119, 105, 116, 104, 100, 114, 97, 119, 97, 108, 95, 97, 100, 100, 114, 101, 115, 115, 34, 58, 34, 69, 116, 104, 65, 100, 100, 114, 101, 115, 115, 34, 44, 34, 114, 97, 110, 100, 97, 111, 95, 99, 111, 109, 109, 105, 116, 109, 101, 110, 116, 34, 58, 34, 72, 97, 115, 104, 50, 53, 54, 34, 44, 34, 98, 97, 108,97, 110, 99, 101, 34, 58, 34, 105, 110, 116, 54, 52, 34, 44, 34, 115, 116, 97, 114, 116, 95, 100, 121, 110, 97, 115, 116, 121, 34, 58, 34, 105, 110, 116, 54, 52, 34, 44, 34, 101, 110, 100, 95, 100, 121, 110, 97, 115, 116, 121, 34, 58, 34, 105, 110, 116, 54, 52, 34, 125, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 17, 103, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 170, 187, 204, 221, 238, 255, 0, 0, 0, 0, 0, 1, 134, 160, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]
  #
  # #####################
  #
  # Char representation
  #
  # @['\x7F', 'E', 'T', 'H', 'E', 'R', 'E', 'U', 'M', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xE2', '9', '\x00', 'V', '\x86', 'z', '\xC0', 'r', '\xC4', '\xCF', '\xCB', ']', 'J', '\xBC', '`', '\xBD', '\xC8', '\xEA', '\x8C', '\xC3', '\x94', '\x1C', 'N', '\xCB', '\x98', 't', '%', 'J', '\xF1', '\xBD', 'K', '(', '\x1D', '{', '\"', 'p', 'u', 'b', 'k', 'e', 'y', '\"', ':', '\"', 'U', 'I', 'n', 't', '2', '5', '6', '\"', ',', '\"', 'w', 'i', 't', 'h', 'd', 'r', 'a', 'w', 'a', 'l', '_', 's', 'h', 'a', 'r', 'd', '\"', ':', '\"', 'i', 'n', 't', '1', '6', '\"', ',', '\"', 'w', 'i', 't', 'h', 'd', 'r', 'a', 'w', 'a', 'l', '_', 'a', 'd', 'd', 'r', 'e', 's', 's', '\"', ':', '\"', 'E', 't', 'h', 'A', 'd', 'd', 'r','e', 's', 's', '\"', ',', '\"', 'r', 'a', 'n', 'd', 'a', 'o', '_', 'c', 'o', 'm', 'm', 'i', 't', 'm', 'e', 'n', 't', '\"', ':', '\"', 'H', 'a', 's', 'h', '2', '5', '6', '\"', ',', '\"', 'b', 'a', 'l', 'a', 'n', 'c', 'e', '\"', ':', '\"', 'i', 'n', 't', '6', '4', '\"', ',', '\"', 's', 't', 'a', 'r', 't', '_', 'd', 'y', 'n', 'a', 's', 't', 'y', '\"', ':', '\"', 'i', 'n', 't', '6', '4', '\"', ',', '\"', 'e', 'n', 'd', '_', 'd', 'y', 'n', 'a', 's', 't', 'y', '\"', ':', '\"', 'i', 'n', 't', '6', '4', '\"', '}', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\xFF', '\x11', 'g', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x12', '4', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xAA', '\xBB', '\xCC', '\xDD', '\xEE', '\xFF', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\x86', '\xA0', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x02']
  #
  # #####################
  #
  # Hex representation
  #
  # 7f455448455245554d010000000000000000e2390056867ac072c4cfcb5d4abc60bdc8ea8cc3941c4ecb9874254af1bd4b281d7b227075626b6579223a2255496e74323536222c227769746864726177616c5f7368617264223a22696e743136222c227769746864726177616c5f61646472657373223a2245746841646472657373222c2272616e64616f5f636f6d6d69746d656e74223a2248617368323536222c2262616c616e6365223a22696e743634222c2273746172745f64796e61737479223a22696e743634222c22656e645f64796e61737479223a22696e743634227dffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff116700000000000000000000000000000000000012340000000000000000000000000000000000000000000000000000aabbccddeeff00000000000186a000000000000000010000000000000002
