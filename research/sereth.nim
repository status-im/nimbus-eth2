import
  json, macros, sequtils, endians,
  eth_common, stint, nimcrypto, byteutils

type
  ValidatorRecord = object
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
  var jsonType: JsonNode = newJObject()
  for field in impl[2]:
    let (fieldName, fieldType) = ($field[0], $field[1]) # convert name and type to string
    jsonType[fieldName] = %fieldType                    # % creates a JsonNode from the string that we assign to key = fieldName.
  result = newStrLitNode($jsonType)

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
    magic = mapLiterals(['\x61','E','T','H','E','R','E','U','M'], byte)
    version = [byte 1, 0]
    schema = typeToJson(T)

  result = @[]
  result.add magic
  result.add version

  # Offset of the raw data (stored as int64 even on 32-bit platform):
  #   -  9 bytes of magic header
  #   -  2 bytes for version
  #   -  8 bytes for offset (int64)
  #   - 32 bytes for Blake2 hash for raw data
  let
    offset = int64(result.len + sizeof(int64) + sizeof(Hash256) + schema.len)
    metadataStart = result.len + sizeof(int64)

  # Write the offset as a Big Endian int64
  result.setLen(result.len + sizeof(int64))
  bigEndian64(result[result.len - sizeof(int64)].addr, offset.unsafeAddr)

  # Reserve space for Blake2 hash (256-bit / 32 bytes)
  result.setLen(result.len + sizeof(Hash256))

  # Write the schema (we need to reinterpret the string literal as an array of byte)
  result.add cast[array[schema.len, byte]](schema)

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

  # Compute the hash
  result[metadataStart .. metadataStart + sizeof(Hash256)] = blake2_256.digest(result[offset ..< result.len]).data

  # Some reports
  echo "Schema: " & $schema
  echo "Schema size: " & $schema.len
  echo "Raw data offset (== metadata size): " & $offset
  echo "Raw data size (bytes): " & $(result.len - offset)
  echo "Total size (bytes): " & $result.len


when isMainModule:
  let x = ValidatorRecord(
    pubkey: 123456789.u256,
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
  # Raw data offset: 226
  # Raw data size (bytes): 109
  # Total size (bytes): 335
  #
  # #####################
  #
  # Byte representation
  #
  # @[97, 69, 84, 72, 69, 82, 69, 85, 77, 1, 0, 0, 0, 0, 0, 0, 0, 0, 226, 213, 67, 87, 156, 127, 178, 250, 140, 247, 198, 251, 179, 75, 124, 44, 121, 216, 1, 99, 44, 174, 253, 237, 4, 78, 77, 191, 227, 39, 25, 132, 187, 192, 52, 3, 1, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 0,0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 1, 160, 183, 145, 236, 254, 127, 0, 0, 45, 169, 48, 3, 1, 0, 0, 0, 169, 13, 0, 0, 0, 0, 0, 0, 53, 158, 48, 3, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0,0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 91, 205, 21, 17, 103, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 170, 187, 204, 221, 238, 255, 0, 0, 0, 0, 0, 1, 134, 160, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2]
  #
  # #####################
  #
  # Char representation
  #
  # @['a', 'E', 'T', 'H', 'E', 'R', 'E', 'U', 'M', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xE2', '\xD5', 'C', 'W', '\x9C', '\x7F', '\xB2', '\xFA', '\x8C', '\xF7', '\xC6', '\xFB', '\xB3', 'K', '|', ',', 'y', '\xD8', '\x01', 'c', ',', '\xAE', '\xFD', '\xED', '\x04', 'N', 'M', '\xBF', '\xE3', '\'', '\x19', '\x84', '\xBB', '\xC0', '4', '\x03', '\x01', '\x00', '\x00', '\x00', '\x0E', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\c', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x04', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x1A', '\x00','\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x06', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\c', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\f', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x0E', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\xA0', '\xB7', '\x91', '\xEC', '\xFE', '\x7F', '\x00', '\x00', '-','\xA9', '0', '\x03', '\x01', '\x00', '\x00', '\x00', '\xA9', '\c', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '5', '\x9E', '0', '\x03', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\x00', '\x01', '\x00', '\x00', '\x00', '\x04', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', ' ', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '@', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\f', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\f', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x02', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\a', '[', '\xCD', '\x15', '\x11', 'g', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x12', '4', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\xAA', '\xBB', '\xCC', '\xDD', '\xEE', '\xFF', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\x86', '\xA0', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x01', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x02']
  #
  # #####################
  #
  # Hex representation
  #
  # 61455448455245554d010000000000000000e2d543579c7fb2fa8cf7c6fbb34b7c2c79d801632caefded044e4dbfe3271984bb501306010000000e000000000000000d000000000000000400000000000000000000000000000000000000000000001a0000000000000006000000000000000d000000000000000c000000000000000e000000000000019827b3e9fe7f000039390f0601000000a90d0000000000002d2e0f060100000000000100010000000400000000000000200000000000000040000000000000000c000000000000000c000000000000000200000000000000000000000000000000000000000000000000000000000000000000075bcd15116700000000000000000000000000000000000012340000000000000000000000000000000000000000000000000000aabbccddeeff00000000000186a000000000000000010000000000000002
