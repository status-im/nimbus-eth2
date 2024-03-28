{.push raises: [].}

import
  chronos,
  libp2p/switch,
  ../spec/[eth2_ssz_serialization]

type
  ErrorMsg = List[byte, 256]
  MessageInfo = object
    protocolMounter: MounterProc

  MounterProc = proc() {.gcsafe, raises: [].}

proc sendErrorResponse(conn: Connection,
                       errMsg: ErrorMsg) = discard
proc readChunkPayload(conn: Connection,
                       MsgType: type): MsgType =
  try:
    SSZ.decode(default(seq[byte]), MsgType)
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

    const isEmptyMsg = when MsgRec is object:
      when totalSerializedFields(MsgRec) == 0: true
      else: false
    else:
      false

    let msg =
      try:
        when isEmptyMsg:
          default(MsgRec)
        else:
          readChunkPayload(conn, MsgRec)
      finally:
        discard

    try:
      discard
    except CatchableError:
      sendErrorResponse(conn, default(ErrorMsg))

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
