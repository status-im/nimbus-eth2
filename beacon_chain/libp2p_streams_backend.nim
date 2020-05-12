# TODO: How can this be tested?
proc uncompressFramedStream*(conn: Connection, output: OutputStream): Future[Result[void, cstring]] {.async.} =
  var header: array[STREAM_HEADER.len, byte]
  try:
    await conn.readExactly(addr header[0], header.len)
  except LPStreamEOFError:
    return err "Unexpected EOF before snappy header"

  if header != STREAM_HEADER.toOpenArrayByte(0, STREAM_HEADER.len-1):
    return err "Incorrect snappy header"

  var uncompressedData = newSeq[byte](MAX_UNCOMPRESSED_DATA_LEN)

  while true:
    var frameHeader: array[4, byte]
    try:
      await conn.readExactly(addr frameHeader[0], frameHeader.len)
    except LPStreamEOFError:
      return ok()

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
        uncompressedLen = snappyUncompress(frameData.toOpenArray(4, frameData.len - 1), uncompressedData)

      if uncompressedLen <= 0:
        return err "Failed to decompress snappy frame"

      if not checkCrcAndAppend(output, uncompressedData.toOpenArray(0, uncompressedLen-1), crc):
        return err "Snappy content CRC checksum failed"

    elif id == UNCOMPRESSED_DATA_IDENTIFIER:
      if dataLen < 4:
        return err "Snappy frame size too low to contain CRC checksum"

      let crc = uint32.fromBytesLE frameData[0..3]
      if not checkCrcAndAppend(output, frameData.toOpenArray(4, frameData.len - 1), crc):
        return err "Snappy content CRC checksum failed"

    elif id < 0x80:
      # Reserved unskippable chunks (chunk types 0x02-0x7f)
      # if we encounter this type of chunk, stop decoding
      # the spec says it is an error
      return err "Invalid snappy chunk type"

    else:
      # Reserved skippable chunks (chunk types 0x80-0xfe)
      # including STREAM_HEADER (0xff) should be skipped
      continue

proc readChunk(conn: Connection,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe.}

proc readSizePrefix(conn: Connection,
                    deadline: Future[void]): Future[int] {.async.} =
  trace "about to read msg size prefix"
  var parser: VarintParser[uint64, ProtoBuf]
  while true:
    var nextByte: byte
    var readNextByte = conn.readExactly(addr nextByte, 1)
    await readNextByte or deadline
    if not readNextByte.finished:
      trace "size prefix byte not received in time"
      return -1
    case parser.feedByte(nextByte)
    of Done:
      let res = parser.getResult
      if res > uint64(MAX_CHUNK_SIZE):
        trace "size prefix outside of range", res
        return -1
      else:
        trace "got size prefix", res
        return int(res)
    of Overflow:
      trace "size prefix overflow"
      return -1
    of Incomplete:
      continue

proc readMsgBytes(conn: Connection,
                  withResponseCode: bool,
                  deadline: Future[void]): Future[Bytes] {.async.} =
  trace "about to read message bytes", withResponseCode

  try:
    if withResponseCode:
      var responseCode: byte
      trace "about to read response code"
      var readResponseCode = conn.readExactly(addr responseCode, 1)
      try:
        await readResponseCode or deadline
      except LPStreamEOFError:
        trace "end of stream received"
        return

      if not readResponseCode.finished:
        trace "response code not received in time"
        return

      if responseCode > ResponseCode.high.byte:
        trace "invalid response code", responseCode
        return

      logScope: responseCode = ResponseCode(responseCode)
      trace "got response code"

      case ResponseCode(responseCode)
      of InvalidRequest, ServerError:
        let responseErrMsg = await conn.readChunk(string, false, deadline)
        debug "P2P request resulted in error", responseErrMsg
        return

      of Success:
        # The response is OK, the execution continues below
        discard

    var sizePrefix = await conn.readSizePrefix(deadline)
    trace "got msg size prefix", sizePrefix

    if sizePrefix == -1:
      debug "Failed to read an incoming message size prefix", peer = conn.peerId
      return

    if sizePrefix == 0:
      debug "Received SSZ with zero size", peer = conn.peerId
      return

    trace "about to read msg bytes", len = sizePrefix
    var msgBytes = newSeq[byte](sizePrefix)
    var readBody = conn.readExactly(addr msgBytes[0], sizePrefix)
    await readBody or deadline
    if not readBody.finished:
      trace "msg bytes not received in time"
      return

    trace "got message bytes", len = sizePrefix
    return msgBytes

  except TransportIncompleteError:
    return @[]

proc readChunk(conn: Connection,
               MsgType: type,
               withResponseCode: bool,
               deadline: Future[void]): Future[Option[MsgType]] {.gcsafe, async.} =
  var msgBytes = await conn.readMsgBytes(withResponseCode, deadline)
  try:
    if msgBytes.len > 0:
      return some SSZ.decode(msgBytes, MsgType)
  except SerializationError as err:
    debug "Failed to decode a network message",
          msgBytes, errMsg = err.formatMsg("<msg>")
    return

proc readResponse(
       conn: Connection,
       MsgType: type,
       deadline: Future[void]): Future[Option[MsgType]] {.gcsafe, async.} =

  when MsgType is seq:
    type E = ElemType(MsgType)
    var results: MsgType
    while true:
      let nextRes = await conn.readChunk(E, true, deadline)
      if nextRes.isNone: break
      results.add nextRes.get
    if results.len > 0:
      return some(results)
  else:
    return await conn.readChunk(MsgType, true, deadline)
