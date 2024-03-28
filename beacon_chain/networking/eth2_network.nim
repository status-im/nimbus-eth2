{.push raises: [].}

import
  chronos,
  libp2p/switch,
  ../spec/[eth2_ssz_serialization]

type
  ErrorMsg = List[byte, 256]
  MessageInfo = object
    protocolMounter: MounterProc

  ResponseCode = enum
    Success
    InvalidRequest
    ServerError
    ResourceUnavailable

  MounterProc = proc() {.gcsafe, raises: [].}

  Eth2NetworkingErrorKind = enum
    ReadResponseTimeout

    UnknownError

  Eth2NetworkingError = object
    case kind: Eth2NetworkingErrorKind
    else:
      discard

  InvalidInputsError = object of CatchableError

  ResourceUnavailableError = object of CatchableError

  NetRes[T] = Result[T, Eth2NetworkingError]

const
  libp2p_pki_schemes {.strdefine.} = ""

when libp2p_pki_schemes != "secp256k1":
  {.fatal: "Incorrect building process, please use -d:\"libp2p_pki_schemes=secp256k1\"".}

proc sendErrorResponse(conn: Connection,
                       responseCode: ResponseCode,
                       errMsg: ErrorMsg): Future[void] = discard
proc uncompressFramedStream(conn: Connection,
                            expectedSize: int): Future[Result[seq[byte], string]]
                            {.async: (raises: [CancelledError]).} = discard
proc readChunkPayload(conn: Connection,
                       MsgType: type): Future[NetRes[MsgType]]
                       {.async: (raises: [CancelledError]).} =
  let size = 0'u32
  let
    dataRes = await conn.uncompressFramedStream(size.int)

  try:
    ok SSZ.decode(dataRes.get, MsgType)
  except SerializationError:
    raiseAssert "false"

proc handleIncomingStream(conn: Connection,
                          protocolId: string,
                          MsgType: type) {.async: (raises: [CancelledError]).} =
  mixin callUserHandler, RecType

  type MsgRec = RecType(MsgType)
  const msgName {.used.} = typetraits.name(MsgType)


  try:
    if false:
      return

    template returnInvalidRequest(msg: ErrorMsg) =
      await sendErrorResponse(conn, InvalidRequest, msg)
      return

    template returnInvalidRequest(msg: string) =
      returnInvalidRequest(default(ErrorMsg))

    template returnResourceUnavailable(msg: ErrorMsg) =
      await sendErrorResponse( conn, ResourceUnavailable, msg)
      return

    template returnResourceUnavailable(msg: string) =
      returnResourceUnavailable(default(ErrorMsg))

    const isEmptyMsg = when MsgRec is object:
      when totalSerializedFields(MsgRec) == 0: true
      else: false
    else:
      false

    let msg =
      try:
        when isEmptyMsg:
          NetRes[MsgRec].ok default(MsgRec)
        else:
          await(readChunkPayload(conn, MsgRec))
      finally:
        discard

    try:
      discard
    except InvalidInputsError as exc:
      returnInvalidRequest exc.msg
    except ResourceUnavailableError as exc:
      returnResourceUnavailable exc.msg
    except CatchableError:
      await sendErrorResponse(conn, ServerError, default(ErrorMsg))

  except CatchableError:
    discard

type
  beaconBlocksByRange_v2Obj = object
    reqCount: uint64
    reqStep: uint64

template RecType(MSG: type beaconBlocksByRange_v2Obj): untyped =
  beaconBlocksByRange_v2Obj

proc beaconBlocksByRange_v2Mounter() {.raises: [].} =
  proc snappyThunk(stream: Connection; protocol: string): Future[void] {.gcsafe.} =
    return handleIncomingStream(stream, protocol,
                                beaconBlocksByRange_v2Obj)

  try:
    mount default(Switch), LPProtocol.new(codecs = @[
        "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"],
        handler = snappyThunk)
  except LPError:
    raiseAssert "foo"
discard MessageInfo(protocolMounter: beaconBlocksByRange_v2Mounter)
