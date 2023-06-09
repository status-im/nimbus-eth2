# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import libp2p/[peerid, multiaddress], json_serialization
export json_serialization

proc writeValue*(writer: var JsonWriter, value: PeerId) {.
    raises: [Defect, IOError].} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var PeerId) {.
    raises: [Defect, IOError, SerializationError].} =
  let res = PeerId.init reader.readValue(string)
  if res.isOk:
    value = res.get()
  else:
    raiseUnexpectedValue(reader, $res.error)

proc writeValue*(writer: var JsonWriter, value: MultiAddress) {.
    raises: [Defect, IOError].} =
  writer.writeValue $value

proc readValue*(reader: var JsonReader, value: var MultiAddress) {.
    raises: [Defect, IOError, SerializationError].} =
  let res = MultiAddress.init reader.readValue(string)
  if res.isOk:
    value = res.value
  else:
    raiseUnexpectedValue(reader, $res.error)
