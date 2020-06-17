import libp2p/daemon/daemonapi, json_serialization
export json_serialization

proc writeValue*(writer: var JsonWriter, value: PeerID) {.inline.} =
  writer.writeValue value.pretty

proc readValue*(reader: var JsonReader, value: var PeerID) {.inline.} =
  value = PeerID.init reader.readValue(string)

proc writeValue*(writer: var JsonWriter, value: MultiAddress) {.inline.} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var MultiAddress) {.inline.} =
  let addressRes = MultiAddress.init reader.readValue(string)
  if addressRes.isOk:
    value = addressRes.value
  else:
    raiseUnexpectedValue(reader, "Invalid MultiAddress value")

