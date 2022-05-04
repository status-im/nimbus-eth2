# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# TODO: How can this be tested?
proc uncompressFramedStream*(conn: Connection,
                             expectedSize: int): Future[Result[seq[byte], cstring]]
                            {.async.} =
  var header: array[framingHeader.len, byte]
  try:
    await conn.readExactly(addr header[0], header.len)
  except LPStreamEOFError, LPStreamIncompleteError:
    return err "Unexpected EOF before snappy header"

  if header != framingHeader:
    return err "Incorrect snappy header"

  static:
    doAssert maxCompressedFrameDataLen >= maxUncompressedFrameDataLen.uint64

  var
    frameData = newSeq[byte](maxCompressedFrameDataLen + 4)
    output = newSeqUninitialized[byte](expectedSize)
    written = 0

  while written < expectedSize:
    var frameHeader: array[4, byte]
    try:
      await conn.readExactly(addr frameHeader[0], frameHeader.len)
    except LPStreamEOFError, LPStreamIncompleteError:
      return err "Snappy frame header missing"

    let (id, dataLen) = decodeFrameHeader(frameHeader)

    if dataLen > frameData.len:
      # In theory, compressed frames could be bigger and still result in a
      # valid, small snappy frame, but this would mean they are not getting
      # compressed correctly
      return err "Snappy frame too big"

    if dataLen > 0:
      try:
        await conn.readExactly(addr frameData[0], dataLen)
      except LPStreamEOFError, LPStreamIncompleteError:
        return err "Incomplete snappy frame"

    if id == chunkCompressed:
      if dataLen < 6: # At least CRC + 2 bytes of frame data
        return err "Compressed snappy frame too small"

      let
        crc = uint32.fromBytesLE frameData.toOpenArray(0, 3)
        uncompressed =
          snappy.uncompress(
            frameData.toOpenArray(4, dataLen - 1),
            output.toOpenArray(written, output.high)).valueOr:
              return err "Failed to decompress content"

      if maskedCrc(
          output.toOpenArray(written, written + uncompressed-1)) != crc:
        return err "Snappy content CRC checksum failed"

      written += uncompressed

    elif id == chunkUncompressed:
      if dataLen < 5: # At least one byte of data
        return err "Uncompressed snappy frame too small"

      let uncompressed = dataLen - 4

      if uncompressed > maxUncompressedFrameDataLen.int:
        return err "Snappy frame size too large"

      if uncompressed > output.len - written:
        return err "Too much data"

      let crc = uint32.fromBytesLE frameData.toOpenArray(0, 3)
      if maskedCrc(frameData.toOpenArray(4, dataLen - 1)) != crc:
        return err "Snappy content CRC checksum failed"

      output[written..<written + uncompressed] =
        frameData.toOpenArray(4, dataLen-1)
      written += uncompressed

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

proc readChunkPayload*(conn: Connection, peer: Peer,
                       maxChunkSize: uint32,
                       MsgType: type): Future[NetRes[MsgType]] {.async.} =
  let sm = now(chronos.Moment)
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

  # The `size.int` conversion is safe because `size` is bounded to `MAX_CHUNK_SIZE`
  let data = await conn.uncompressFramedStream(size.int)
  if data.isOk:
    # `10` is the maximum size of variable integer on wire, so error could
    # not be significant.
    peer.updateNetThroughput(now(chronos.Moment) - sm,
                              uint64(10 + size))
    return ok SSZ.decode(data.get(), MsgType)
  else:
    debug "Snappy decompression/read failed", msg = $data.error, conn
    return neterr InvalidSnappyBytes

proc readResponseChunk(conn: Connection, peer: Peer, maxChunkSize: uint32,
                       MsgType: typedesc): Future[NetRes[MsgType]] {.async.} =
  mixin readChunkPayload

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
    of InvalidRequest, ServerError, ResourceUnavailable:
      let
        errorMsgChunk = await readChunkPayload(
          conn, peer, maxChunkSize, ErrorMsg)
        errorMsg = if errorMsgChunk.isOk: errorMsgChunk.value
                   else: return err(errorMsgChunk.error)
        errorMsgStr = toPrettyString(errorMsg.asSeq)
      debug "Error response from peer", responseCode, errMsg = errorMsgStr
      return err Eth2NetworkingError(kind: ReceivedErrorResponse,
                                     responseCode: responseCode,
                                     errorMsg: errorMsgStr)
    of Success:
      discard

    return await readChunkPayload(conn, peer, maxChunkSize, MsgType)

  except LPStreamEOFError, LPStreamIncompleteError:
    return neterr UnexpectedEOF

proc readResponse(conn: Connection, peer: Peer, maxChunkSize: uint32,
                  MsgType: type, timeout: Duration): Future[NetRes[MsgType]] {.async.} =
  when MsgType is seq:
    type E = ElemType(MsgType)
    var results: MsgType
    while true:
      # Because we interleave networking with response processing, it may
      # happen that reading all chunks takes longer than a strict dealine
      # timeout would allow, so we allow each chunk a new timeout instead.
      # The problem is exacerbated by the large number of round-trips to the
      # poll loop that each future along the way causes.
      trace "reading chunk", conn
      let nextFut = conn.readResponseChunk(peer, maxChunkSize, E)
      if not await nextFut.withTimeout(timeout):
        return neterr(ReadResponseTimeout)
      let nextRes = nextFut.read()
      if nextRes.isErr:
        if nextRes.error.kind == PotentiallyExpectedEOF:
          trace "EOF chunk", conn, err = nextRes.error

          return ok results
        trace "Error chunk", conn, err = nextRes.error

        return err nextRes.error
      else:
        trace "Got chunk", conn
        results.add nextRes.value
  else:
    let nextFut = conn.readResponseChunk(peer, maxChunkSize, MsgType)
    if not await nextFut.withTimeout(timeout):
      return neterr(ReadResponseTimeout)
    return nextFut.read()
