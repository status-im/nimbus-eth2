import libp2p/daemon/daemonapi, json_serialization
export json_serialization

proc writeValue*(writer: var JsonWriter, value: PeerID) {.inline.} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var PeerID) {.inline.} =
  let res = PeerID.init reader.readValue(string)
  if res.isOk:
    value = res.get()
  else:
    raiseUnexpectedValue(reader, $res.error)

proc writeValue*(writer: var JsonWriter, value: MultiAddress) {.inline.} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var MultiAddress) {.inline.} =
  let res = MultiAddress.init reader.readValue(string)
  if res.isOk:
    value = res.value
  else:
    raiseUnexpectedValue(reader, $res.error)

