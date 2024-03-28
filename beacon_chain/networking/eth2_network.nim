import
  ../spec/[eth2_ssz_serialization]

type
  ErrorMsg = List[byte, 256]
  MessageInfo = object
    protocolMounter: MounterProc

  MounterProc = proc() {.gcsafe, raises: [].}

proc sendErrorResponse(errMsg: ErrorMsg) = discard
proc readChunkPayload(MsgType: type): MsgType =
  try:
    SSZ.decode(default(seq[byte]), MsgType)
  except SerializationError:
    raiseAssert "false"

proc handleIncomingStream(protocolId: string,
                          MsgType: type) =
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
          readChunkPayload(MsgRec)
      finally:
        discard

    try:
      discard
    except CatchableError:
      sendErrorResponse(default(ErrorMsg))

  except CatchableError:
    discard

type
  beaconBlocksByRange_v2Obj = object
    reqCount: uint64
    reqStep: uint64

template RecType(MSG: type beaconBlocksByRange_v2Obj): untyped =
  beaconBlocksByRange_v2Obj

proc mount2*[T](proto: T) =
  discard
proc beaconBlocksByRange_v2Mounter() {.raises: [].} =
  proc snappyThunk(protocol: string) {.gcsafe.} =
    handleIncomingStream(protocol,
                                beaconBlocksByRange_v2Obj)

  mount2(snappyThunk)
discard MessageInfo(protocolMounter: beaconBlocksByRange_v2Mounter)
