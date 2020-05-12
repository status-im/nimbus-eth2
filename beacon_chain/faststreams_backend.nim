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

proc readSizePrefix(s: AsyncInputStream, maxSize: uint64): Future[int] {.async.} =
  trace "about to read msg size prefix"
  var parser: VarintParser[uint64, ProtoBuf]
  while s.readable:
    case parser.feedByte(s.read)
    of Done:
      let res = parser.getResult
      if res > maxSize:
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

proc readSszValue(s: AsyncInputStream, MsgType: type): Future[MsgType] {.async.} =
  let size = await s.readSizePrefix(uint64(MAX_CHUNK_SIZE))
  if size > 0 and s.readable(size):
    s.withReadableRange(size, r):
      return r.readValue(SSZ, MsgType)
  else:
    raise newException(CatchableError,
                      "Failed to read an incoming message size prefix")

proc readResponseCode(s: AsyncInputStream): Future[Result[bool, string]] {.async.} =
  if s.readable:
    let responseCode = s.read
    static: assert responseCode.type.low == 0
    if responseCode > ResponseCode.high.byte:
      return err("Invalid response code")

    case ResponseCode(responseCode):
    of InvalidRequest, ServerError:
      return err(await s.readSszValue(string))
    of Success:
      return ok true
  else:
    return ok false

proc readChunk(s: AsyncInputStream,
               MsgType: typedesc): Future[Option[MsgType]] {.async.} =
  let rc = await s.readResponseCode()
  if rc.isOk:
    if rc[]:
      return some(await readSszValue(s, MsgType))
  else:
    trace "Failed to read response code",
           reason = rc.error

proc readResponse(s: AsyncInputStream,
                  MsgType: type): Future[Option[MsgType]] {.gcsafe, async.} =
  when MsgType is seq:
    type E = ElemType(MsgType)
    var results: MsgType
    while true:
      let nextRes = await s.readChunk(E)
      if nextRes.isNone: break
      results.add nextRes.get
    if results.len > 0:
      return some(results)
  else:
    return await s.readChunk(MsgType)

