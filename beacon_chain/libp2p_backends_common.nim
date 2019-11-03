type
  ResponseCode* = enum
    Success
    InvalidRequest
    ServerError

const
  defaultIncomingReqTimeout = 5000
  HandshakeTimeout = FaultOrError

  # Spec constants
  # https://github.com/ethereum/eth2.0-specs/blob/dev/specs/networking/p2p-interface.md#eth-20-network-interaction-domains
  REQ_RESP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  GOSSIP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  TTFB_TIMEOUT* = 5.seconds
  RESP_TIMEOUT* = 10.seconds

  readTimeoutErrorMsg = "Exceeded read timeout for a request"

logScope:
  topic = "libp2p"

template libp2pProtocol*(name: string, version: int) {.pragma.}

proc getRequestProtoName(fn: NimNode): NimNode =
  # `getCustomPragmaVal` doesn't work yet on regular nnkProcDef nodes
  # (TODO: file as an issue)

  let pragmas = fn.pragma
  if pragmas.kind == nnkPragma and pragmas.len > 0:
    for pragma in pragmas:
      if pragma.len > 0 and $pragma[0] == "libp2pProtocol":
        let protoName = $(pragma[1])
        let protoVer = $(pragma[2].intVal)
        return newLit("/eth2/beacon_chain/req/" & protoName & "/" & protoVer & "/ssz")

  return newLit("")

