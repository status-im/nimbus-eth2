# TODO: How can this be tested?
proc uncompressFramedStream*(conn: Connection,
                             output: OutputStream,
                             expectedSize: int): Future[Result[void, cstring]]
                            {.async.} =
  var header: array[STREAM_HEADER.len, byte]
  try:
    await conn.readExactly(addr header[0], header.len)
  except LPStreamEOFError:
    return err "Unexpected EOF before snappy header"

  if header != STREAM_HEADER.toOpenArrayByte(0, STREAM_HEADER.high):
    return err "Incorrect snappy header"

  var totalBytesDecompressed = 0
  var uncompressedData = newSeq[byte](MAX_UNCOMPRESSED_DATA_LEN)

  while totalBytesDecompressed < expectedSize:
    var frameHeader: array[4, byte]
    try:
      await conn.readExactly(addr frameHeader[0], frameHeader.len)
    except LPStreamEOFError:
      break

    let x = uint32.fromBytesLE frameHeader
    let id = x and 0xFF
    let dataLen = (x shr 8).int

    if dataLen > MAX_COMPRESSED_DATA_LEN:
      return err "invalid snappy frame length"

    var frameData = newSeq[byte](dataLen)
    try:
      await conn.readExactly(addr frameData[0], dataLen)
    except LPStreamEOFError:
      return err "Incomplete snappy frame"

    if id == COMPRESSED_DATA_IDENTIFIER:
      if dataLen < 4:
        return err "Snappy frame size too low to contain CRC checksum"

      let
        crc = uint32.fromBytesLE frameData[0..3]
        uncompressedLen = snappyUncompress(frameData.toOpenArray(4, frameData.high), uncompressedData)

      if uncompressedLen <= 0:
        return err "Failed to decompress snappy frame"

      if not checkCrcAndAppend(output, uncompressedData.toOpenArray(0, uncompressedLen-1), crc):
        return err "Snappy content CRC checksum failed"

      totalBytesDecompressed += uncompressedLen

    elif id == UNCOMPRESSED_DATA_IDENTIFIER:
      if dataLen < 4:
        return err "Snappy frame size too low to contain CRC checksum"

      let crc = uint32.fromBytesLE frameData[0..3]
      if not checkCrcAndAppend(output, frameData.toOpenArray(4, frameData.high), crc):
        return err "Snappy content CRC checksum failed"

      totalBytesDecompressed += frameData.len - 4

    elif id < 0x80:
      # Reserved unskippable chunks (chunk types 0x02-0x7f)
      # if we encounter this type of chunk, stop decoding
      # the spec says it is an error
      return err "Invalid snappy chunk type"

    else:
      # Reserved skippable chunks (chunk types 0x80-0xfe)
      # including STREAM_HEADER (0xff) should be skipped
      continue

  return ok()

proc readSizePrefix(conn: Connection,
                    maxSize: uint32): Future[NetRes[uint32]] {.async.} =
  trace "about to read msg size prefix"
  var parser: VarintParser[uint32, ProtoBuf]
  try:
    while true:
      var nextByte: byte
      await conn.readExactly(addr nextByte, 1)
      case parser.feedByte(nextByte)
      of Done:
        let res = parser.getResult
        if res > maxSize:
          return neterr SizePrefixOverflow
        else:
          return ok res
      of Overflow:
        return neterr SizePrefixOverflow
      of Incomplete:
        continue
  except LPStreamEOFError:
    return neterr UnexpectedEOF

proc readChunkPayload(conn: Connection,
                      noSnappy: bool,
                      MsgType: type): Future[NetRes[MsgType]] {.async.} =
  let prefix = await readSizePrefix(conn, MAX_CHUNK_SIZE)
  let size = if prefix.isOk: prefix.value.int
             else: return err(prefix.error)

  if size > 0:
    if noSnappy:
      var bytes = newSeq[byte](size)
      await conn.readExactly(addr bytes[0], bytes.len)
      return ok SSZ.decode(bytes, MsgType)
    else:
      var snappyOutput = memoryOutput()
      let status = await conn.uncompressFramedStream(snappyOutput, size)
      if status.isOk:
        var decompressedBytes = snappyOutput.getOutput
        if decompressedBytes.len != size:
          return neterr InvalidSnappyBytes
        else:
          return ok SSZ.decode(decompressedBytes, MsgType)
      else:
        return neterr InvalidSnappyBytes
  else:
    return neterr ZeroSizePrefix

proc readResponseChunk(conn: Connection,
                       noSnappy: bool,
                       MsgType: typedesc): Future[NetRes[MsgType]] {.async.} =
  try:
    var responseCodeByte: byte
    try:
      await conn.readExactly(addr responseCodeByte, 1)
    except LPStreamEOFError:
      return neterr PotentiallyExpectedEOF

    static: assert ResponseCode.low.ord == 0
    if responseCodeByte > ResponseCode.high.byte:
      return neterr InvalidResponseCode

    let responseCode = ResponseCode responseCodeByte
    case responseCode:
    of InvalidRequest, ServerError:
      let errorMsgChunk = await readChunkPayload(conn, noSnappy, string)
      let errorMsg = if errorMsgChunk.isOk: errorMsgChunk.value
                     else: return err(errorMsgChunk.error)
      return err Eth2NetworkingError(kind: ReceivedErrorResponse,
                                     responseCode: responseCode,
                                     errorMsg: errorMsg)
    of Success:
      discard

    return await readChunkPayload(conn, noSnappy, MsgType)

  except LPStreamEOFError:
    return neterr UnexpectedEOF

proc readResponse(conn: Connection,
                  noSnappy: bool,
                  MsgType: type): Future[NetRes[MsgType]] {.gcsafe, async.} =
  when MsgType is seq:
    type E = ElemType(MsgType)
    var results: MsgType
    while true:
      let nextRes = await conn.readResponseChunk(noSnappy, E)
      if nextRes.isErr:
        if nextRes.error.kind == PotentiallyExpectedEOF:
          return ok results
        return err nextRes.error
      else:
        results.add nextRes.value
  else:
    return await conn.readResponseChunk(noSnappy, MsgType)

