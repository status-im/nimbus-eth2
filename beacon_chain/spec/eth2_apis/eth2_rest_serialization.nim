# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/typetraits
import stew/[results, base10, byteutils, endians2], presto/common,
       libp2p/peerid, serialization,
       json_serialization, json_serialization/std/[options, net],
       nimcrypto/utils as ncrutils
import ".."/forks, ".."/datatypes/[phase0, altair, merge],
       ".."/".."/ssz/ssz_serialization,
       "."/rest_types

export
  results, peerid, common, serialization, json_serialization, options, net,
  rest_types

Json.createFlavor RestJson

const
  DecimalSet = {'0' .. '9'}
    # Base10 (decimal) set of chars
  ValidatorKeySize = RawPubKeySize * 2
    # Size of `ValidatorPubKey` hexadecimal value (without 0x)
  ValidatorSigSize = RawSigSize * 2
    # Size of `ValidatorSig` hexadecimal value (without 0x)
  RootHashSize = sizeof(Eth2Digest) * 2
    # Size of `xxx_root` hexadecimal value (without 0x)

type
  RestGenericError* = object
    code*: uint64
    message*: string
    stacktraces*: Option[seq[string]]

  RestAttestationError* = object
    code*: uint64
    message*: string
    failures*: seq[RestAttestationsFailure]

  EncodeTypes* =
    AttesterSlashing |
    ProposerSlashing |
    phase0.SignedBeaconBlock |
    altair.SignedBeaconBlock |
    SignedVoluntaryExit

  EncodeArrays* =
    seq[ValidatorIndex] |
    seq[Attestation] |
    seq[SignedAggregateAndProof] |
    seq[RestCommitteeSubscription]

  DecodeTypes* =
    DataEnclosedObject |
    GetBlockV2Response |
    ProduceBlockResponseV2 |
    DataMetaEnclosedObject |
    DataRootEnclosedObject |
    RestAttestationError |
    RestGenericError

{.push raises: [Defect].}

proc prepareJsonResponse*(t: typedesc[RestApiResponse], d: auto): seq[byte] =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("data", d)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  res

proc jsonResponseWRoot*(t: typedesc[RestApiResponse], data: auto,
                        dependent_root: Eth2Digest): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("dependent_root", dependent_root)
        writer.writeField("data", data)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponse*(t: typedesc[RestApiResponse], data: auto): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("data", data)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponsePlain*(t: typedesc[RestApiResponse],
                        data: auto): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.writeValue(data)
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponseWMeta*(t: typedesc[RestApiResponse],
                        data: auto, meta: auto): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("data", data)
        writer.writeField("meta", meta)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(res, Http200, "application/json")

proc jsonMsgResponse*(t: typedesc[RestApiResponse],
                      msg: string = ""): RestApiResponse =
  let data =
    block:
      var default: seq[byte]
      try:
        var defstrings: seq[string]
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", "200")
        writer.writeField("message", msg)
        writer.writeField("stacktrace", defstrings)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(data, Http200, "application/json")

proc jsonError*(t: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = ""): RestApiResponse =
  let data =
    block:
      var default: string
      try:
        var defstrings: seq[string]
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", Base10.toString(uint64(status.toInt())))
        writer.writeField("message", msg)
        writer.writeField("stacktrace", defstrings)
        writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.error(status, data, "application/json")

proc jsonError*(t: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "", stacktrace: string): RestApiResponse =
  let data =
    block:
      var default: string
      try:
        var defstrings: seq[string]
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", Base10.toString(uint64(status.toInt())))
        writer.writeField("message", msg)
        if len(stacktrace) > 0:
          writer.writeField("stacktrace", [stacktrace])
        else:
          writer.writeField("stacktrace", defstrings)
        writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.error(status, data, "application/json")

proc jsonError*(t: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "",
                stacktraces: openarray[string]): RestApiResponse =
  let data =
    block:
      var default: string
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", Base10.toString(uint64(status.toInt())))
        writer.writeField("message", msg)
        writer.writeField("stacktrace", stacktraces)
        writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.error(status, data, "application/json")

proc jsonErrorList*(t: typedesc[RestApiResponse],
                    status: HttpCode = Http200,
                    msg: string = "", failures: auto): RestApiResponse =
  let data =
    block:
      var default: string
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", Base10.toString(uint64(status.toInt())))
        writer.writeField("message", msg)
        writer.writeField("failures", failures)
        writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.error(status, data, "application/json")

proc sszResponse*(t: typedesc[RestApiResponse], data: auto): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = SszWriter.init(stream)
        writer.writeValue(data)
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(res, Http200, "application/octet-stream")

template hexOriginal(data: openarray[byte]): string =
  "0x" & ncrutils.toHex(data, true)

## uint64
proc writeValue*(w: var JsonWriter[RestJson], value: uint64) {.
     raises: [IOError, Defect].} =
  writeValue(w, Base10.toString(value))

proc readValue*(reader: var JsonReader[RestJson], value: var uint64) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    value = res.get()
  else:
    reader.raiseUnexpectedValue($res.error())

## byte
proc writeValue*(w: var JsonWriter[RestJson], value: byte) {.
     raises: [IOError, Defect].} =
  var data: array[1, byte]
  data[0] = value
  writeValue(w, hexOriginal(data))

proc readValue*(reader: var JsonReader[RestJson], value: var byte) {.
     raises: [IOError, SerializationError, Defect].} =
  var data: array[1, byte]
  try:
    hexToByteArray(reader.readValue(string), data)
    value = data[0]
  except ValueError:
    raiseUnexpectedValue(reader,
                         "byte value should be a valid hex string")

## DomainType
proc writeValue*(w: var JsonWriter[RestJson], value: DomainType) {.
     raises: [IOError, Defect].} =
  writeValue(w, hexOriginal(uint32(value).toBytesLE()))

proc readValue*(reader: var JsonReader[RestJson], value: var DomainType) {.
     raises: [IOError, SerializationError, Defect].} =
  var data: array[4, byte]
  try:
    hexToByteArray(reader.readValue(string), data)
    let res = uint32.fromBytesLE(data)
    if res >= uint32(low(DomainType)) and res <= uint32(high(DomainType)):
      value = cast[DomainType](res)
    else:
      raiseUnexpectedValue(reader, "Incorrect DomainType value")
  except ValueError:
    raiseUnexpectedValue(reader,
                         "DomainType value should be a valid hex string")

## Slot
proc writeValue*(writer: var JsonWriter[RestJson], value: Slot) {.
     raises: [IOError, Defect].} =
  writeValue(writer, Base10.toString(uint64(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var Slot) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    value = Slot(res.get())
  else:
    reader.raiseUnexpectedValue($res.error())

## Epoch
proc writeValue*(writer: var JsonWriter[RestJson], value: Epoch) {.
     raises: [IOError, Defect].} =
  writeValue(writer, Base10.toString(uint64(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var Epoch) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    value = Epoch(res.get())
  else:
    reader.raiseUnexpectedValue($res.error())

## ValidatorIndex
proc writeValue*(writer: var JsonWriter[RestJson], value: ValidatorIndex) {.
     raises: [IOError, Defect].} =
  writeValue(writer, Base10.toString(uint64(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var ValidatorIndex) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    let v = res.get()
    if v < VALIDATOR_REGISTRY_LIMIT:
      value = ValidatorIndex(v)
    else:
      reader.raiseUnexpectedValue(
        "Validator index is bigger then VALIDATOR_REGISTRY_LIMIT")
  else:
    reader.raiseUnexpectedValue($res.error())

## RestValidatorIndex
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: RestValidatorIndex) {.
     raises: [IOError, Defect].} =
  writeValue(writer, Base10.toString(uint64(value)))

proc readValue*(reader: var JsonReader[RestJson],
                value: var RestValidatorIndex) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    let v = res.get()
    value = RestValidatorIndex(v)
  else:
    reader.raiseUnexpectedValue($res.error())

## CommitteeIndex
proc writeValue*(writer: var JsonWriter[RestJson], value: CommitteeIndex) {.
     raises: [IOError, Defect].} =
  writeValue(writer, Base10.toString(uint64(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var CommitteeIndex) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    value = CommitteeIndex(res.get())
  else:
    reader.raiseUnexpectedValue($res.error())

## ValidatorSig
proc writeValue*(writer: var JsonWriter[RestJson], value: ValidatorSig) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(toRaw(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var ValidatorSig) {.
     raises: [IOError, SerializationError, Defect].} =
  let hexValue = reader.readValue(string)
  let res = ValidatorSig.fromHex(hexValue)
  if res.isOk():
    value = res.get()
  else:
    reader.raiseUnexpectedValue($res.error())

## TrustedSig
proc writeValue*(writer: var JsonWriter[RestJson], value: TrustedSig) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(toRaw(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var TrustedSig) {.
     raises: [IOError, SerializationError, Defect].} =
  let hexValue = reader.readValue(string)
  let res = ValidatorSig.fromHex(hexValue)
  if res.isOk():
    value = cast[TrustedSig](res.get())
  else:
    reader.raiseUnexpectedValue($res.error())

## ValidatorPubKey
proc writeValue*(writer: var JsonWriter[RestJson], value: ValidatorPubKey) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(toRaw(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var ValidatorPubKey) {.
     raises: [IOError, SerializationError, Defect].} =
  let hexValue = reader.readValue(string)
  let res = ValidatorPubKey.fromHex(hexValue)
  if res.isOk():
    value = res.get()
  else:
    reader.raiseUnexpectedValue($res.error())

## BitSeq
proc readValue*(reader: var JsonReader[RestJson], value: var BitSeq) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    value = BitSeq hexToSeqByte(reader.readValue(string))
  except ValueError:
    raiseUnexpectedValue(reader, "A BitSeq value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: BitSeq) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(value.bytes()))

## BitList
proc readValue*(reader: var JsonReader[RestJson], value: var BitList) {.
     raises: [IOError, SerializationError, Defect].} =
  type T = type(value)
  value = T readValue(reader, BitSeq)

proc writeValue*(writer: var JsonWriter[RestJson], value: BitList) {.
     raises: [IOError, Defect].} =
  writeValue(writer, BitSeq value)

## Eth2Digest
proc readValue*(reader: var JsonReader[RestJson], value: var Eth2Digest) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), value.data)
  except ValueError:
    raiseUnexpectedValue(reader,
                         "Eth2Digest value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: Eth2Digest) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(value.data))

## BloomLogs
proc readValue*(reader: var JsonReader[RestJson], value: var BloomLogs) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), value.data)
  except ValueError:
    raiseUnexpectedValue(reader,
                         "BloomLogs value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: BloomLogs) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(value.data))

## HashArray
proc readValue*(reader: var JsonReader[RestJson], value: var HashArray) {.
     raises: [IOError, SerializationError, Defect].} =
  readValue(reader, value.data)

proc writeValue*(writer: var JsonWriter[RestJson], value: HashArray) {.
     raises: [IOError, Defect].} =
  writeValue(writer, value.data)

## HashList
proc readValue*(reader: var JsonReader[RestJson], value: var HashList) {.
     raises: [IOError, SerializationError, Defect].} =
  readValue(reader, value.data)

proc writeValue*(writer: var JsonWriter[RestJson], value: HashList) {.
     raises: [IOError, Defect].} =
  writeValue(writer, value.data)

## Eth1Address
proc readValue*(reader: var JsonReader[RestJson], value: var Eth1Address) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), distinctBase(value))
  except ValueError:
    raiseUnexpectedValue(reader,
                         "Eth1Address value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: Eth1Address) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(distinctBase(value)))

## Version
proc readValue*(reader: var JsonReader[RestJson], value: var Version) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), distinctBase(value))
  except ValueError:
    raiseUnexpectedValue(reader,
                         "Version value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: Version) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(distinctBase(value)))

## ForkDigest
proc readValue*(reader: var JsonReader[RestJson], value: var ForkDigest) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), distinctBase(value))
  except ValueError:
    raiseUnexpectedValue(reader,
                         "ForkDigest value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: ForkDigest) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(distinctBase(value)))

## GraffitiBytes
proc readValue*(reader: var JsonReader[RestJson], value: var GraffitiBytes) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), distinctBase(value))
  except ValueError:
    raiseUnexpectedValue(reader,
                         "GraffitiBytes value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: GraffitiBytes) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(distinctBase(value)))

## ForkedBeaconBlock
proc readValue*(reader: var JsonReader[RestJson],
                value: var ForkedBeaconBlock) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    version: Option[BeaconBlockFork]
    data: Option[JsonString]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "version":
      if version.isSome():
        reader.raiseUnexpectedField("Multiple version fields found",
                                    "ForkedBeaconBlock")
      let vres = reader.readValue(string)
      case vres
      of "phase0":
        version = some(BeaconBlockFork.Phase0)
      of "altair":
        version = some(BeaconBlockFork.Altair)
      else:
        reader.raiseUnexpectedValue("Incorrect version field value")
    of "data":
      if data.isSome():
        reader.raiseUnexpectedField("Multiple data fields found",
                                    "ForkedBeaconBlock")
      data = some(reader.readValue(JsonString))
    else:
      reader.raiseUnexpectedField(fieldName, "ForkedBeaconBlock")

  if version.isNone():
    reader.raiseUnexpectedValue("Field version is missing")
  if data.isNone():
    reader.raiseUnexpectedValue("Field data is missing")

  case version.get():
  of BeaconBlockFork.Phase0:
    let res =
      try:
        some(RestJson.decode(string(data.get()), phase0.BeaconBlock,
                             requireAllFields = true))
      except SerializationError:
        none[phase0.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect phase0 block format")
    value = ForkedBeaconBlock.init(res.get())
  of BeaconBlockFork.Altair:
    let res =
      try:
        some(RestJson.decode(string(data.get()), altair.BeaconBlock,
                             requireAllFields = true))
      except SerializationError:
        none[altair.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect altair block format")
    value = ForkedBeaconBlock.init(res.get())

proc writeValue*(writer: var JsonWriter[RestJson], value: ForkedBeaconBlock) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  case value.kind
  of BeaconBlockFork.Phase0:
    writer.writeField("version", "phase0")
    writer.writeField("data", value.phase0Block)
  of BeaconBlockFork.Altair:
    writer.writeField("version", "altair")
    writer.writeField("data", value.altairBlock)
  writer.endRecord()

## ForkedSignedBeaconBlock
proc readValue*(reader: var JsonReader[RestJson],
                value: var ForkedSignedBeaconBlock) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    version: Option[BeaconBlockFork]
    data: Option[JsonString]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "version":
      if version.isSome():
        reader.raiseUnexpectedField("Multiple version fields found",
                                    "ForkedSignedBeaconBlock")
      let vres = reader.readValue(string)
      case vres
      of "phase0":
        version = some(BeaconBlockFork.Phase0)
      of "altair":
        version = some(BeaconBlockFork.Altair)
      else:
        reader.raiseUnexpectedValue("Incorrect version field value")
    of "data":
      if data.isSome():
        reader.raiseUnexpectedField("Multiple data fields found",
                                    "ForkedSignedBeaconBlock")
      data = some(reader.readValue(JsonString))
    else:
      reader.raiseUnexpectedField(fieldName, "ForkedSignedBeaconBlock")

  if version.isNone():
    reader.raiseUnexpectedValue("Field version is missing")
  if data.isNone():
    reader.raiseUnexpectedValue("Field data is missing")

  case version.get():
  of BeaconBlockFork.Phase0:
    let res =
      try:
        some(RestJson.decode(string(data.get()), phase0.SignedBeaconBlock,
                             requireAllFields = true))
      except SerializationError:
        none[phase0.SignedBeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect phase0 block format")
    value = ForkedSignedBeaconBlock.init(res.get())
  of BeaconBlockFork.Altair:
    let res =
      try:
        some(RestJson.decode(string(data.get()), altair.SignedBeaconBlock,
                             requireAllFields = true))
      except SerializationError:
        none[altair.SignedBeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect altair block format")
    value = ForkedSignedBeaconBlock.init(res.get())

proc writeValue*(writer: var JsonWriter[RestJson],
                 value: ForkedSignedBeaconBlock) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  case value.kind
  of BeaconBlockFork.Phase0:
    writer.writeField("version", "phase0")
    writer.writeField("data", value.phase0Block)
  of BeaconBlockFork.Altair:
    writer.writeField("version", "altair")
    writer.writeField("data", value.altairBlock)
  writer.endRecord()

proc toSszType*(v: BeaconBlockFork): auto =
  case v
  of BeaconBlockFork.Phase0:
    [byte('p'), byte('h'), byte('a'), byte('s'), byte('e'), byte('0')]
  of BeaconBlockFork.Altair:
    [byte('a'), byte('l'), byte('t'), byte('a'), byte('i'), byte('r')]

template toSszType*(v: BeaconStateFork): auto =
  case v
  of BeaconStateFork.forkPhase0:
    [byte('p'), byte('h'), byte('a'), byte('s'), byte('e'), byte('0')]
  of BeaconStateFork.forkAltair:
    [byte('a'), byte('l'), byte('t'), byte('a'), byte('i'), byte('r')]

proc parseRoot(value: string): Result[Eth2Digest, cstring] =
  try:
    ok(Eth2Digest(data: hexToByteArray[32](value)))
  except ValueError:
    err("Unable to decode root value")

proc decodeBody*[T](t: typedesc[T],
                    body: ContentBody): Result[T, cstring] =
  if body.contentType != "application/json":
    return err("Unsupported content type")
  let data =
    try:
      RestJson.decode(cast[string](body.data), T)
    except SerializationError:
      return err("Unable to deserialize data")
    except CatchableError:
      return err("Unexpected deserialization error")
  ok(data)

RestJson.useCustomSerialization(phase0.BeaconState.justification_bits):
  read:
    let s = reader.readValue(string)
    if s.len != 4:
      raiseUnexpectedValue(reader, "A string with 4 characters expected")
    try:
      hexToByteArray(s, 1)[0]
    except ValueError:
      raiseUnexpectedValue(reader,
                          "The `justification_bits` value must be a hex string")
  write:
    writer.writeValue "0x" & toHex([value])

proc encodeBytes*[T: EncodeTypes](value: T,
                                  contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    let data =
      block:
        try:
          var stream = memoryOutput()
          var writer = JsonWriter[RestJson].init(stream)
          writer.writeValue(value)
          stream.getOutput(seq[byte])
        except IOError:
          return err("Input/output error")
        except SerializationError:
          return err("Serialization error")
    ok(data)
  else:
    err("Content-Type not supported")

proc encodeBytes*[T: EncodeArrays](value: T,
                                   contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    let data =
      block:
        try:
          var stream = memoryOutput()
          var writer = JsonWriter[RestJson].init(stream)
          writer.writeArray(value)
          stream.getOutput(seq[byte])
        except IOError:
          return err("Input/output error")
        except SerializationError:
          return err("Serialization error")
    ok(data)
  else:
    err("Content-Type not supported")

proc decodeBytes*[T: DecodeTypes](t: typedesc[T], value: openarray[byte],
                                  contentType: string): RestResult[T] =
  case contentType
  of "application/json":
    try:
      ok RestJson.decode(value, T)
    except SerializationError as exc:
      err("Serialization error")
  else:
    err("Content-Type not supported")

proc encodeString*(value: string): RestResult[string] =
  ok(value)

proc encodeString*(value: Epoch|Slot|CommitteeIndex): RestResult[string] =
  ok(Base10.toString(uint64(value)))

proc encodeString*(value: ValidatorSig): RestResult[string] =
  ok(hexOriginal(toRaw(value)))

proc encodeString*(value: GraffitiBytes): RestResult[string] =
  ok(hexOriginal(distinctBase(value)))

proc encodeString*(value: Eth2Digest): RestResult[string] =
  ok(hexOriginal(value.data))

proc encodeString*(value: ValidatorIdent): RestResult[string] =
  case value.kind
  of ValidatorQueryKind.Index:
    ok(Base10.toString(uint64(value.index)))
  of ValidatorQueryKind.Key:
    ok(hexOriginal(toRaw(value.key)))

proc encodeString*(value: StateIdent): RestResult[string] =
  case value.kind
  of StateQueryKind.Slot:
    ok(Base10.toString(uint64(value.slot)))
  of StateQueryKind.Root:
    ok(hexOriginal(value.root.data))
  of StateQueryKind.Named:
    case value.value
    of StateIdentType.Head:
      ok("head")
    of StateIdentType.Genesis:
      ok("genesis")
    of StateIdentType.Finalized:
      ok("finalized")
    of StateIdentType.Justified:
      ok("justified")

proc encodeString*(value: BlockIdent): RestResult[string] =
  case value.kind
  of BlockQueryKind.Slot:
    ok(Base10.toString(uint64(value.slot)))
  of BlockQueryKind.Root:
    ok(hexOriginal(value.root.data))
  of BlockQueryKind.Named:
    case value.value
    of BlockIdentType.Head:
      ok("head")
    of BlockIdentType.Genesis:
      ok("genesis")
    of BlockIdentType.Finalized:
      ok("finalized")

proc decodeString*(t: typedesc[PeerStateKind],
                   value: string): Result[PeerStateKind, cstring] =
  case value
  of "disconnected":
    ok(PeerStateKind.Disconnected)
  of "connecting":
    ok(PeerStateKind.Connecting)
  of "connected":
    ok(PeerStateKind.Connected)
  of "disconnecting":
    ok(PeerStateKind.Disconnecting)
  else:
    err("Incorrect peer's state value")

proc encodeString*(value: PeerStateKind): Result[string, cstring] =
  case value
  of PeerStateKind.Disconnected:
    ok("disconnected")
  of PeerStateKind.Connecting:
    ok("connecting")
  of PeerStateKind.Connected:
    ok("connected")
  of PeerStateKind.Disconnecting:
    ok("disconnecting")

proc decodeString*(t: typedesc[PeerDirectKind],
                   value: string): Result[PeerDirectKind, cstring] =
  case value
  of "inbound":
    ok(PeerDirectKind.Inbound)
  of "outbound":
    ok(PeerDirectKind.Outbound)
  else:
    err("Incorrect peer's direction value")

proc encodeString*(value: PeerDirectKind): Result[string, cstring] =
  case value
  of PeerDirectKind.Inbound:
    ok("inbound")
  of PeerDirectKind.Outbound:
    ok("outbound")

proc encodeString*(peerid: PeerID): Result[string, cstring] =
  ok($peerid)

proc decodeString*(t: typedesc[EventTopic],
                   value: string): Result[EventTopic, cstring] =
  case value
  of "head":
    ok(EventTopic.Head)
  of "block":
    ok(EventTopic.Block)
  of "attestation":
    ok(EventTopic.Attestation)
  of "voluntary_exit":
    ok(EventTopic.VoluntaryExit)
  of "finalized_checkpoint":
    ok(EventTopic.FinalizedCheckpoint)
  of "chain_reorg":
    ok(EventTopic.ChainReorg)
  else:
    err("Incorrect event's topic value")

proc decodeString*(t: typedesc[ValidatorSig],
                   value: string): Result[ValidatorSig, cstring] =
  if len(value) != ValidatorSigSize + 2:
    return err("Incorrect validator signature value length")
  if value[0] != '0' and value[1] != 'x':
    return err("Incorrect validator signature encoding")
  ValidatorSig.fromHex(value)

proc decodeString*(t: typedesc[GraffitiBytes],
                   value: string): Result[GraffitiBytes, cstring] =
  try:
    ok(GraffitiBytes.init(value))
  except ValueError:
    err("Unable to decode graffiti value")

proc decodeString*(t: typedesc[string],
                   value: string): Result[string, cstring] =
  ok(value)

proc decodeString*(t: typedesc[Slot], value: string): Result[Slot, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(Slot(res))

proc decodeString*(t: typedesc[Epoch], value: string): Result[Epoch, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(Epoch(res))

proc decodeString*(t: typedesc[StateIdent],
                   value: string): Result[StateIdent, cstring] =
  if len(value) > 2:
    if (value[0] == '0') and (value[1] == 'x'):
      if len(value) != RootHashSize + 2:
        err("Incorrect state root value length")
      else:
        let res = ? parseRoot(value)
        ok(StateIdent(kind: StateQueryKind.Root, root: res))
    elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
      let res = ? Base10.decode(uint64, value)
      ok(StateIdent(kind: StateQueryKind.Slot, slot: Slot(res)))
    else:
      case value
      of "head":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Head))
      of "genesis":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Genesis))
      of "finalized":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Finalized))
      of "justified":
        ok(StateIdent(kind: StateQueryKind.Named,
                      value: StateIdentType.Justified))
      else:
        err("Incorrect state identifier value")
  else:
    let res = ? Base10.decode(uint64, value)
    ok(StateIdent(kind: StateQueryKind.Slot, slot: Slot(res)))

proc decodeString*(t: typedesc[BlockIdent],
                   value: string): Result[BlockIdent, cstring] =
  if len(value) > 2:
    if (value[0] == '0') and (value[1] == 'x'):
      if len(value) != RootHashSize + 2:
        err("Incorrect block root value length")
      else:
        let res = ? parseRoot(value)
        ok(BlockIdent(kind: BlockQueryKind.Root, root: res))
    elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
      let res = ? Base10.decode(uint64, value)
      ok(BlockIdent(kind: BlockQueryKind.Slot, slot: Slot(res)))
    else:
      case value
        of "head":
          ok(BlockIdent(kind: BlockQueryKind.Named,
                        value: BlockIdentType.Head))
        of "genesis":
          ok(BlockIdent(kind: BlockQueryKind.Named,
                        value: BlockIdentType.Genesis))
        of "finalized":
          ok(BlockIdent(kind: BlockQueryKind.Named,
                        value: BlockIdentType.Finalized))
        else:
          err("Incorrect block identifier value")
  else:
    let res = ? Base10.decode(uint64, value)
    ok(BlockIdent(kind: BlockQueryKind.Slot, slot: Slot(res)))

proc decodeString*(t: typedesc[ValidatorIdent],
                   value: string): Result[ValidatorIdent, cstring] =
  if len(value) > 2:
    if (value[0] == '0') and (value[1] == 'x'):
      if len(value) != ValidatorKeySize + 2:
        err("Incorrect validator's key value length")
      else:
        let res = ? ValidatorPubKey.fromHex(value)
        ok(ValidatorIdent(kind: ValidatorQueryKind.Key,
                          key: res))
    elif (value[0] in DecimalSet) and (value[1] in DecimalSet):
      let res = ? Base10.decode(uint64, value)
      ok(ValidatorIdent(kind: ValidatorQueryKind.Index,
                        index: RestValidatorIndex(res)))
    else:
      err("Incorrect validator identifier value")
  else:
    let res = ? Base10.decode(uint64, value)
    ok(ValidatorIdent(kind: ValidatorQueryKind.Index,
                      index: RestValidatorIndex(res)))

proc decodeString*(t: typedesc[PeerID],
                   value: string): Result[PeerID, cstring] =
  PeerID.init(value)

proc decodeString*(t: typedesc[CommitteeIndex],
                   value: string): Result[CommitteeIndex, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(CommitteeIndex(res))

proc decodeString*(t: typedesc[Eth2Digest],
                   value: string): Result[Eth2Digest, cstring] =
  if len(value) != RootHashSize + 2:
    return err("Incorrect root value length")
  if value[0] != '0' and value[1] != 'x':
    return err("Incorrect root value encoding")
  parseRoot(value)

proc decodeString*(t: typedesc[ValidatorFilter],
                   value: string): Result[ValidatorFilter, cstring] =
  case value
  of "pending_initialized":
    ok({ValidatorFilterKind.PendingInitialized})
  of "pending_queued":
    ok({ValidatorFilterKind.PendingQueued})
  of "active_ongoing":
    ok({ValidatorFilterKind.ActiveOngoing})
  of "active_exiting":
    ok({ValidatorFilterKind.ActiveExiting})
  of "active_slashed":
    ok({ValidatorFilterKind.ActiveSlashed})
  of "exited_unslashed":
    ok({ValidatorFilterKind.ExitedUnslashed})
  of "exited_slashed":
    ok({ValidatorFilterKind.ExitedSlashed})
  of "withdrawal_possible":
    ok({ValidatorFilterKind.WithdrawalPossible})
  of "withdrawal_done":
    ok({ValidatorFilterKind.WithdrawalDone})
  of "pending":
    ok({
      ValidatorFilterKind.PendingInitialized,
      ValidatorFilterKind.PendingQueued
    })
  of "active":
    ok({
      ValidatorFilterKind.ActiveOngoing,
      ValidatorFilterKind.ActiveExiting,
      ValidatorFilterKind.ActiveSlashed
    })
  of "exited":
    ok({
      ValidatorFilterKind.ExitedUnslashed,
      ValidatorFilterKind.ExitedSlashed
    })
  of "withdrawal":
    ok({
      ValidatorFilterKind.WithdrawalPossible,
      ValidatorFilterKind.WithdrawalDone
    })
  else:
    err("Incorrect validator state identifier value")
