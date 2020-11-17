import libp2p/daemon/daemonapi, json_serialization
export json_serialization

proc writeValue*(writer: var JsonWriter, value: PeerID) =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var PeerID) =
  let res = PeerID.init reader.readValue(string)
  if res.isOk:
    value = res.get()
  else:
    raiseUnexpectedValue(reader, $res.error)

proc writeValue*(writer: var JsonWriter, value: MultiAddress) =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var MultiAddress) =
  let res = MultiAddress.init reader.readValue(string)
  if res.isOk:
    value = res.value
  else:
    raiseUnexpectedValue(reader, $res.error)

