# TODO: How can this be tested?
proc uncompressFramedStream*(conn: Connection,
                             expectedSize: int): Future[Result[seq[byte], cstring]]
                            {.async.} =
  var header: array[STREAM_HEADER.len, byte]
  try:
    await conn.readExactly(addr header[0], header.len)
  except LPStreamEOFError, LPStreamIncompleteError:
    return err "Unexpected EOF before snappy header"

  if header != STREAM_HEADER.toOpenArrayByte(0, STREAM_HEADER.high):
    return err "Incorrect snappy header"

  var
    uncompressedData = newSeq[byte](MAX_UNCOMPRESSED_DATA_LEN)
    frameData = newSeq[byte](MAX_COMPRESSED_DATA_LEN)
    output = newSeqOfCap[byte](expectedSize)

  while output.len < expectedSize:
    var frameHeader: array[4, byte]
    try:
      await conn.readExactly(addr frameHeader[0], frameHeader.len)
    except LPStreamEOFError, LPStreamIncompleteError:
      break

    let x = uint32.fromBytesLE frameHeader
    let id = x and 0xFF
    let dataLen = (x shr 8).int

    if dataLen > MAX_COMPRESSED_DATA_LEN:
      return err "invalid snappy frame length"

    if dataLen > 0:
      try:
        await conn.readExactly(addr frameData[0], dataLen)
      except LPStreamEOFError, LPStreamIncompleteError:
        return err "Incomplete snappy frame"

    if id == COMPRESSED_DATA_IDENTIFIER:
      if dataLen < 4:
        return err "Snappy frame size too low to contain CRC checksum"

      let
        crc = uint32.fromBytesLE frameData.toOpenArray(0, 3)
        todo = expectedSize - output.len
        uncompressedLen = snappyUncompress(
          frameData.toOpenArray(4, dataLen - 1),
          uncompressedData.toOpenArray(0, min(todo, uncompressedData.len) - 1))

      if uncompressedLen <= 0:
        return err "Failed to decompress snappy frame"
      doAssert output.len + uncompressedLen <= expectedSize,
        "enforced by `min` above"

      if not checkCrc(uncompressedData.toOpenArray(0, uncompressedLen-1), crc):
        return err "Snappy content CRC checksum failed"

      output.add uncompressedData.toOpenArray(0, uncompressedLen-1)

    elif id == UNCOMPRESSED_DATA_IDENTIFIER:
      if dataLen < 4:
        return err "Snappy frame size too low to contain CRC checksum"

      if output.len + dataLen - 4 > expectedSize:
        return err "Too much data"

      let crc = uint32.fromBytesLE frameData.toOpenArray(0, 3)
      if not checkCrc(frameData.toOpenArray(4, dataLen - 1), crc):
        return err "Snappy content CRC checksum failed"

      output.add frameData.toOpenArray(4, dataLen-1)

    elif id < 0x80:
      # Reserved unskippable chunks (chunk types 0x02-0x7f)
      # if we encounter this type of chunk, stop decoding
      # the spec says it is an error
      return err "Invalid snappy chunk type"

    else:
      # Reserved skippable chunks (chunk types 0x80-0xfe)
      # including STREAM_HEADER (0xff) should be skipped
      continue

  return ok output

proc readChunkPayload(conn: Connection,
                      noSnappy: bool,
                      MsgType: type): Future[NetRes[MsgType]] {.async.} =
  let size =
    try: await conn.readVarint()
    except LPStreamEOFError: #, LPStreamIncompleteError, InvalidVarintError
      # TODO compiler error - haha, uncaught exception
      # Error: unhandled exception: closureiters.nim(322, 17) `c[i].kind == nkType`  [AssertionError]
      return neterr UnexpectedEOF
    except LPStreamIncompleteError:
      return neterr UnexpectedEOF
    except InvalidVarintError:
      return neterr UnexpectedEOF

  if size > MAX_CHUNK_SIZE:
    return neterr SizePrefixOverflow
  if size == 0:
    return neterr ZeroSizePrefix

  if noSnappy:
    var bytes = newSeq[byte](size.int)
    await conn.readExactly(addr bytes[0], bytes.len)
    return ok SSZ.decode(bytes, MsgType)
  else:
    let data = await conn.uncompressFramedStream(size.int)
    if data.isOk:
      return ok SSZ.decode(data.get(), MsgType)
    else:
      return neterr InvalidSnappyBytes

proc readResponseChunk(conn: Connection,
                       noSnappy: bool,
                       MsgType: typedesc): Future[NetRes[MsgType]] {.async.} =
  try:
    var responseCodeByte: byte
    try:
      await conn.readExactly(addr responseCodeByte, 1)
    except LPStreamEOFError, LPStreamIncompleteError:
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

  except LPStreamEOFError, LPStreamIncompleteError:
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
