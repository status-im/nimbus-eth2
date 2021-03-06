type
  LibP2PInputStream = ref object of InputStream
    conn: Connection

const
  closingErrMsg = "Failed to close LibP2P stream"
  readingErrMsg = "Failed to read from LibP2P stream"

proc libp2pReadOnce(s: LibP2PInputStream,
                    dst: pointer, dstLen: Natural): Future[Natural] {.async.} =
  fsTranslateErrors readingErrMsg:
    try:
      return implementSingleRead(s.buffers, dst, dstLen, ReadFlags {},
                                 readStartAddr, readLen):
        await s.conn.readOnce(readStartAddr, readLen)
    except LPStreamEOFError:
      s.buffers.eofReached = true

proc libp2pCloseWait(s: LibP2PInputStream) {.async.} =
  fsTranslateErrors closingErrMsg:
    await safeClose(s.conn)

# TODO: Use the Raising type here
let libp2pInputVTable = InputStreamVTable(
  readSync: proc (s: InputStream, dst: pointer, dstLen: Natural): Natural
                 {.nimcall, gcsafe, raises: [IOError, Defect].} =
    doAssert(false, "synchronous reading is not allowed")
  ,
  readAsync: proc (s: InputStream, dst: pointer, dstLen: Natural): Future[Natural]
                  {.nimcall, gcsafe, raises: [IOError, Defect].} =
    fsTranslateErrors "Unexpected exception from merely forwarding a future":
      return libp2pReadOnce(Libp2pInputStream s, dst, dstLen)
  ,
  closeSync: proc (s: InputStream)
                  {.nimcall, gcsafe, raises: [IOError, Defect].} =
    fsTranslateErrors closingErrMsg:
      s.closeFut = Libp2pInputStream(s).conn.close()
  ,
  closeAsync: proc (s: InputStream): Future[void]
                   {.nimcall, gcsafe, raises: [IOError, Defect].} =
    fsTranslateErrors "Unexpected exception from merely forwarding a future":
      return libp2pCloseWait(Libp2pInputStream s)
)

func libp2pInput*(conn: Connection,
                  pageSize = defaultPageSize): AsyncInputStream =
  AsyncInputStream LibP2PInputStream(
    vtable: vtableAddr libp2pInputVTable,
    buffers: initPageBuffers(pageSize),
    conn: conn)

proc readSizePrefix(s: AsyncInputStream,
                    maxSize: uint32): Future[NetRes[uint32]] {.async.} =
  var parser: VarintParser[uint32, ProtoBuf]
  while s.readable:
    case parser.feedByte(s.read)
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

  return neterr UnexpectedEOF

proc readSszValue(s: AsyncInputStream,
                  size: int,
                  MsgType: type): Future[NetRes[MsgType]] {.async.} =
  if s.readable(size):
    s.withReadableRange(size, r):
      return r.readValue(SSZ, MsgType)
  else:
    return neterr UnexpectedEOF

proc readChunkPayload(s: AsyncInputStream,
                      noSnappy: bool,
                      MsgType: type): Future[NetRes[MsgType]] {.async.} =
  let prefix = await readSizePrefix(s, MAX_CHUNK_SIZE)
  let size = if prefix.isOk: prefix.value.int
             else: return err(prefix.error)

  if size > 0:
    let processingFut = if noSnappy:
      readSszValue(s, size, MsgType)
    else:
      executePipeline(uncompressFramedStream,
                      readSszValue(size, MsgType))

    return await processingFut
  else:
    return neterr ZeroSizePrefix

proc readResponseChunk(s: AsyncInputStream,
                       noSnappy: bool,
                       MsgType: typedesc): Future[NetRes[MsgType]] {.async.} =
  let responseCodeByte = s.read

  static: assert ResponseCode.low.ord == 0
  if responseCodeByte > ResponseCode.high.byte:
    return neterr InvalidResponseCode

  let responseCode = ResponseCode responseCodeByte
  case responseCode:
  of InvalidRequest, ServerError:
    let errorMsgChunk = await readChunkPayload(s, noSnappy, string)
    let errorMsg = if errorMsgChunk.isOk: errorMsgChunk.value
                   else: return err(errorMsgChunk.error)
    return err Eth2NetworkingError(kind: ReceivedErrorResponse,
                                   responseCode: responseCode,
                                   errorMsg: errorMsg)
  of Success:
    discard

  return await readChunkPayload(s, noSnappy, MsgType)

proc readResponse(s: AsyncInputStream,
                  noSnappy: bool,
                  MsgType: type): Future[NetRes[MsgType]] {.gcsafe, async.} =
  when MsgType is seq:
    type E = ElemType(MsgType)
    var results: MsgType
    while s.readable:
      results.add(? await s.readResponseChunk(noSnappy, E))
    return ok results
  else:
    if s.readable:
      return await s.readResponseChunk(noSnappy, MsgType)
    else:
      return neterr UnexpectedEOF

