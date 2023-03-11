# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[typetraits, strutils]
import stew/[assign2, results, base10, byteutils], presto/common,
       libp2p/peerid, serialization, json_serialization,
       json_serialization/std/[options, net, sets],
       chronicles
import ".."/[eth2_ssz_serialization, forks, keystore],
       ".."/../consensus_object_pools/block_pools_types,
       ".."/datatypes/[phase0, altair, bellatrix],
       ".."/mev/[bellatrix_mev, capella_mev],
       ".."/../validators/slashing_protection_common,
       "."/[rest_types, rest_keymanager_types]
import nimcrypto/utils as ncrutils

from ".."/datatypes/capella import SignedBeaconBlock
from ".."/datatypes/deneb import BeaconState

export
  eth2_ssz_serialization, results, peerid, common, serialization, chronicles,
  json_serialization, options, net, sets, rest_types, slashing_protection_common

from web3/ethtypes import BlockHash
export ethtypes.BlockHash

Json.createFlavor RestJson

## The RestJson format implements JSON serialization in the way specified
## by the Beacon API:
##
## https://ethereum.github.io/beacon-APIs/
##
## In this format, we must always set `allowUnknownFields = true` in the
## decode calls in order to conform the following spec:
##
## All JSON responses return the requested data under a data key in the top
## level of their response.  Additional metadata may or may not be present
## in other keys at the top level of the response, dependent on the endpoint.
## The rules that require an increase in version number are as follows:
##
## - no field that is listed in an endpoint shall be removed without an increase
##   in the version number
##
## - no field that is listed in an endpoint shall be altered in terms of format
##   (e.g. from a string to an array) without an increase in the version number
##
## Note that it is possible for a field to be added to an endpoint's data or
## metadata without an increase in the version number.
##
## TODO nim-json-serializations should allow setting up this policy per format
##
## This also means that when new fields are introduced to the object definitions
## below, one must use the `Option[T]` type.

const
  DecimalSet = {'0' .. '9'}
    # Base10 (decimal) set of chars
  ValidatorKeySize = RawPubKeySize * 2
    # Size of `ValidatorPubKey` hexadecimal value (without 0x)
  ValidatorSigSize = RawSigSize * 2
    # Size of `ValidatorSig` hexadecimal value (without 0x)
  RootHashSize = sizeof(Eth2Digest) * 2
    # Size of `xxx_root` hexadecimal value (without 0x)

  ApplicationJsonMediaType* = MediaType.init("application/json")
  TextPlainMediaType* = MediaType.init("text/plain")
  OctetStreamMediaType* = MediaType.init("application/octet-stream")
  UrlEncodedMediaType* = MediaType.init("application/x-www-form-urlencoded")

type
  EmptyBody* = object

  EncodeTypes* =
    AttesterSlashing |
    DeleteKeystoresBody |
    EmptyBody |
    ImportDistributedKeystoresBody |
    ImportRemoteKeystoresBody |
    KeystoresAndSlashingProtection |
    PrepareBeaconProposer |
    ProposerSlashing |
    SetFeeRecipientRequest |
    SetGasLimitRequest |
    bellatrix_mev.SignedBlindedBeaconBlock |
    capella_mev.SignedBlindedBeaconBlock |
    SignedValidatorRegistrationV1 |
    SignedVoluntaryExit |
    Web3SignerRequest

  EncodeOctetTypes* =
    altair.SignedBeaconBlock |
    bellatrix.SignedBeaconBlock |
    capella.SignedBeaconBlock |
    phase0.SignedBeaconBlock

  EncodeArrays* =
    seq[Attestation] |
    seq[PrepareBeaconProposer] |
    seq[RemoteKeystoreInfo] |
    seq[RestCommitteeSubscription] |
    seq[RestSignedContributionAndProof] |
    seq[RestSyncCommitteeMessage] |
    seq[RestSyncCommitteeSubscription] |
    seq[SignedAggregateAndProof] |
    seq[SignedValidatorRegistrationV1] |
    seq[ValidatorIndex]

  DecodeTypes* =
    DataEnclosedObject |
    DataMetaEnclosedObject |
    DataRootEnclosedObject |
    DataOptimisticObject |
    DataVersionEnclosedObject |
    GetBlockV2Response |
    GetDistributedKeystoresResponse |
    GetKeystoresResponse |
    GetRemoteKeystoresResponse |
    GetStateForkResponse |
    GetStateV2Response |
    KeymanagerGenericError |
    KeystoresAndSlashingProtection |
    ListFeeRecipientResponse |
    PrepareBeaconProposer |
    ProduceBlockResponseV2 |
    ProduceBlindedBlockResponse |
    RestIndexedErrorMessage |
    RestErrorMessage |
    RestValidator |
    Web3SignerErrorResponse |
    Web3SignerKeysResponse |
    Web3SignerSignatureResponse |
    Web3SignerStatusResponse |
    GetStateRootResponse |
    GetBlockRootResponse

  RestVersioned*[T] = object
    data*: T
    jsonVersion*: ConsensusFork
    sszContext*: ForkDigest

{.push raises: [].}

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

proc prepareJsonStringResponse*[T: SomeForkedLightClientObject](
    t: typedesc[RestApiResponse], d: RestVersioned[T]): string =
  let res =
    block:
      var default: string
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        withForkyObject(d.data):
          when lcDataFork > LightClientDataFork.None:
            writer.beginRecord()
            writer.writeField("version", d.jsonVersion.toString())
            writer.writeField("data", forkyObject)
            writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  res

proc prepareJsonStringResponse*(t: typedesc[RestApiResponse], d: auto): string =
  let res =
    block:
      var default: string
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.writeValue(d)
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  res

proc jsonResponseWRoot*(t: typedesc[RestApiResponse], data: auto,
                        dependent_root: Eth2Digest,
                        execOpt: Option[bool]): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("dependent_root", dependent_root)
        if execOpt.isSome():
          writer.writeField("execution_optimistic", execOpt.get())
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

proc jsonResponseBlock*(t: typedesc[RestApiResponse],
                        data: ForkedSignedBeaconBlock,
                        execOpt: Option[bool]): RestApiResponse =
  let
    headers = [("eth-consensus-version", data.kind.toString())]
    res =
      block:
        var default: seq[byte]
        try:
          var stream = memoryOutput()
          var writer = JsonWriter[RestJson].init(stream)
          writer.beginRecord()
          writer.writeField("version", data.kind.toString())
          if execOpt.isSome():
            writer.writeField("execution_optimistic", execOpt.get())
          withBlck(data):
            writer.writeField("data", blck)
          writer.endRecord()
          stream.getOutput(seq[byte])
        except SerializationError:
          default
        except IOError:
          default
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseState*(t: typedesc[RestApiResponse],
                        data: ForkedHashedBeaconState,
                        execOpt: Option[bool]): RestApiResponse =
  let
    headers = [("eth-consensus-version", data.kind.toString())]
    res =
      block:
        var default: seq[byte]
        try:
          var stream = memoryOutput()
          var writer = JsonWriter[RestJson].init(stream)
          writer.beginRecord()
          writer.writeField("version", data.kind.toString())
          if execOpt.isSome():
            writer.writeField("execution_optimistic", execOpt.get())
          withState(data):
            writer.writeField("data", forkyState.data)
          writer.endRecord()
          stream.getOutput(seq[byte])
        except SerializationError:
          default
        except IOError:
          default
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseWOpt*(t: typedesc[RestApiResponse], data: auto,
                       execOpt: Option[bool]): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        if execOpt.isSome():
          writer.writeField("execution_optimistic", execOpt.get())
        writer.writeField("data", data)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponseWVersion*(t: typedesc[RestApiResponse], data: auto,
                           version: ConsensusFork): RestApiResponse =
  let
    headers = [("eth-consensus-version", version.toString())]
    res =
      block:
        var default: seq[byte]
        try:
          var stream = memoryOutput()
          var writer = JsonWriter[RestJson].init(stream)
          writer.beginRecord()
          writer.writeField("version", version.toString())
          writer.writeField("data", data)
          writer.endRecord()
          stream.getOutput(seq[byte])
        except SerializationError:
          default
        except IOError:
          default
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseVersioned*[T: SomeForkedLightClientObject](
    t: typedesc[RestApiResponse],
    entries: openArray[RestVersioned[T]]): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        for e in writer.stepwiseArrayCreation(entries):
          withForkyObject(e.data):
            when lcDataFork > LightClientDataFork.None:
              writer.beginRecord()
              writer.writeField("version", e.jsonVersion.toString())
              writer.writeField("data", forkyObject)
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
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", 200)
        writer.writeField("message", msg)
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
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", int(status.toInt()))
        writer.writeField("message", msg)
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
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", int(status.toInt()))
        writer.writeField("message", msg)
        if len(stacktrace) > 0:
          writer.writeField("stacktraces", [stacktrace])
        writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.error(status, data, "application/json")

proc jsonError*(t: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "",
                stacktraces: openArray[string]): RestApiResponse =
  let data =
    block:
      var default: string
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("code", int(status.toInt()))
        writer.writeField("message", msg)
        writer.writeField("stacktraces", stacktraces)
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
        writer.writeField("code", int(status.toInt()))
        writer.writeField("message", msg)
        writer.writeField("failures", failures)
        writer.endRecord()
        stream.getOutput(string)
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.error(status, data, "application/json")

proc sszResponseVersioned*[T: SomeForkedLightClientObject](
    t: typedesc[RestApiResponse],
    entries: openArray[RestVersioned[T]]): RestApiResponse =
  let res =
    block:
      var default: seq[byte]
      try:
        var stream = memoryOutput()
        for e in entries:
          withForkyUpdate(e.data):
            when lcDataFork > LightClientDataFork.None:
              var cursor = stream.delayFixedSizeWrite(sizeof(uint64))
              let initPos = stream.pos
              stream.write e.sszContext.data
              var writer = SszWriter.init(stream)
              writer.writeValue forkyUpdate
              cursor.finalWrite (stream.pos - initPos).uint64.toBytesLE()
        stream.getOutput(seq[byte])
      except SerializationError:
        default
      except IOError:
        default
  RestApiResponse.response(res, Http200, "application/octet-stream")

proc sszResponsePlain*(t: typedesc[RestApiResponse], res: seq[byte],
                       headers: openArray[RestKeyValueTuple] = []
                      ): RestApiResponse =
  RestApiResponse.response(res, Http200, "application/octet-stream",
                           headers = headers)

proc sszResponse*(t: typedesc[RestApiResponse], data: auto,
                  headers: openArray[RestKeyValueTuple] = []
                 ): RestApiResponse =
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
  RestApiResponse.response(res, Http200, "application/octet-stream",
                           headers = headers)

template hexOriginal(data: openArray[byte]): string =
  to0xHex(data)

proc decodeJsonString*[T](t: typedesc[T],
                          data: JsonString): Result[T, cstring] =
  try:
    ok(RestJson.decode(string(data), T,
                       requireAllFields = true,
                       allowUnknownFields = true))
  except SerializationError:
    err("Unable to deserialize data")

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
    reader.raiseUnexpectedValue($res.error() & ": " & svalue)

## uint8
proc writeValue*(w: var JsonWriter[RestJson], value: uint8) {.
     raises: [IOError, Defect].} =
  writeValue(w, Base10.toString(value))

proc readValue*(reader: var JsonReader[RestJson], value: var uint8) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint8, svalue)
  if res.isOk():
    value = res.get()
  else:
    reader.raiseUnexpectedValue($res.error() & ": " & svalue)

## JustificationBits
proc writeValue*(w: var JsonWriter[RestJson], value: JustificationBits) {.
    raises: [IOError, Defect].} =
  w.writeValue hexOriginal([uint8(value)])

proc readValue*(reader: var JsonReader[RestJson], value: var JustificationBits) {.
    raises: [IOError, SerializationError, Defect].} =
  let hex = reader.readValue(string)
  try:
    value = JustificationBits(hexToByteArray(hex, 1)[0])
  except ValueError:
    raiseUnexpectedValue(reader,
                        "The `justification_bits` value must be a hex string")

## UInt256
proc writeValue*(w: var JsonWriter[RestJson], value: UInt256) {.
     raises: [IOError, Defect].} =
  writeValue(w, toString(value))

proc readValue*(reader: var JsonReader[RestJson], value: var UInt256) {.
     raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  try:
    value = parse(svalue, UInt256, 10)
  except ValueError:
    raiseUnexpectedValue(reader,
                         "UInt256 value should be a valid decimal string")

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

## EpochParticipationFlags
proc writeValue*(writer: var JsonWriter[RestJson],
                 epochFlags: EpochParticipationFlags)
                {.raises: [IOError, Defect].} =
  for e in writer.stepwiseArrayCreation(epochFlags.asList):
    writer.writeValue $e

proc readValue*(reader: var JsonReader[RestJson],
                epochFlags: var EpochParticipationFlags)
               {.raises: [SerializationError, IOError, Defect].} =
  for e in reader.readArray(string):
    let parsed = try:
      parseBiggestUInt(e)
    except ValueError as err:
      reader.raiseUnexpectedValue(
        "A string-encoded 8-bit usigned integer value expected")

    if parsed > uint8.high:
      reader.raiseUnexpectedValue(
        "The usigned integer value should fit in 8 bits")

    if not epochFlags.asList.add(uint8(parsed)):
      reader.raiseUnexpectedValue(
        "The participation flags list size exceeds limit")

## ValidatorIndex
proc writeValue*(writer: var JsonWriter[RestJson], value: ValidatorIndex)
                {.raises: [IOError, Defect].} =
  writeValue(writer, Base10.toString(uint64(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var ValidatorIndex)
               {.raises: [IOError, SerializationError, Defect].} =
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

## IndexInSyncCommittee
proc writeValue*(writer: var JsonWriter[RestJson], value: IndexInSyncCommittee)
                {.raises: [IOError, Defect].} =
  writeValue(writer, Base10.toString(distinctBase(value)))

proc readValue*(reader: var JsonReader[RestJson], value: var IndexInSyncCommittee)
               {.raises: [IOError, SerializationError, Defect].} =
  let svalue = reader.readValue(string)
  let res = Base10.decode(uint64, svalue)
  if res.isOk():
    let v = res.get()
    if v < SYNC_COMMITTEE_SIZE:
      value = IndexInSyncCommittee(v)
    else:
      reader.raiseUnexpectedValue(
        "Index in committee is bigger than SYNC_COMMITTEE_SIZE")
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
  writeValue(writer, value.asUInt64)

proc readValue*(reader: var JsonReader[RestJson], value: var CommitteeIndex) {.
     raises: [IOError, SerializationError, Defect].} =
  var v: uint64
  reader.readValue(v)

  let res = CommitteeIndex.init(v)
  if res.isOk():
    value = res.get()
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

## BitArray
proc readValue*(reader: var JsonReader[RestJson], value: var BitArray) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(readValue(reader, string), value.bytes)
  except ValueError:
    raiseUnexpectedValue(reader,
                         "A BitArray value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: BitArray) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(value.bytes))

## BlockHash
proc readValue*(reader: var JsonReader[RestJson], value: var BlockHash) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), distinctBase(value))
  except ValueError:
    raiseUnexpectedValue(reader,
                         "BlockHash value should be a valid hex string")

proc writeValue*(writer: var JsonWriter[RestJson], value: BlockHash) {.
     raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(distinctBase(value)))

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
  value.resetCache()

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

## GraffitiBytes
proc writeValue*(writer: var JsonWriter[RestJson], value: GraffitiBytes)
                {.raises: [IOError, Defect].} =
  writeValue(writer, hexOriginal(distinctBase(value)))

proc readValue*(reader: var JsonReader[RestJson], T: type GraffitiBytes): T
               {.raises: [IOError, SerializationError, Defect].} =
  try:
    init(GraffitiBytes, reader.readValue(string))
  except ValueError as err:
    reader.raiseUnexpectedValue err.msg

## Version | ForkDigest | DomainType | GraffitiBytes
proc readValue*(
    reader: var JsonReader[RestJson],
    value: var (Version | ForkDigest | DomainType | GraffitiBytes)) {.
     raises: [IOError, SerializationError, Defect].} =
  try:
    hexToByteArray(reader.readValue(string), distinctBase(value))
  except ValueError:
    raiseUnexpectedValue(
      reader, "Expected a valid hex string with " & $value.len() & " bytes")

template unrecognizedFieldWarning =
  # TODO: There should be a different notification mechanism for informing the
  #       caller of a deserialization routine for unexpected fields.
  #       The chonicles import in this module should be removed.
  trace "JSON field not recognized by the current version of Nimbus. Consider upgrading",
        fieldName, typeName = typetraits.name(typeof value)

## ForkedBeaconBlock
template prepareForkedBlockReading(
    reader: var JsonReader[RestJson], value: untyped,
    version: var Option[ConsensusFork],
    data: var Option[JsonString],
    blockTypeName: cstring) =
  for fieldName {.inject.} in readObjectFields(reader):
    case fieldName
    of "version":
      if version.isSome():
        reader.raiseUnexpectedField("Multiple version fields found",
                                    blockTypeName)
      let vres = reader.readValue(string).toLowerAscii()
      case vres
      of "phase0":
        version = some(ConsensusFork.Phase0)
      of "altair":
        version = some(ConsensusFork.Altair)
      of "bellatrix":
        version = some(ConsensusFork.Bellatrix)
      of "capella":
        version = some(ConsensusFork.Capella)
      of "deneb":
        version = some(ConsensusFork.Deneb)
      else:
        reader.raiseUnexpectedValue("Incorrect version field value")
    of "block", "block_header", "data":
      if data.isSome():
        reader.raiseUnexpectedField("Multiple block or block_header fields found",
                                    blockTypeName)
      data = some(reader.readValue(JsonString))
    else:
      unrecognizedFieldWarning()

  if version.isNone():
    reader.raiseUnexpectedValue("Field version is missing")
  if data.isNone():
    reader.raiseUnexpectedValue("Field data is missing")

proc readValue*[BlockType: ForkedBeaconBlock](
    reader: var JsonReader[RestJson],
    value: var BlockType) {.raises: [IOError, SerializationError, Defect].} =
  var
    version: Option[ConsensusFork]
    data: Option[JsonString]

  prepareForkedBlockReading(reader, value, version, data, "ForkedBeaconBlock")

  case version.get():
  of ConsensusFork.Phase0:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             phase0.BeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[phase0.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect phase0 block format")
    value = ForkedBeaconBlock.init(res.get()).BlockType
  of ConsensusFork.Altair:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             altair.BeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[altair.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect altair block format")
    value = ForkedBeaconBlock.init(res.get()).BlockType
  of ConsensusFork.Bellatrix:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             bellatrix.BeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[bellatrix.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect bellatrix block format")
    value = ForkedBeaconBlock.init(res.get()).BlockType
  of ConsensusFork.Capella:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             capella.BeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[capella.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect capella block format")
    value = ForkedBeaconBlock.init(res.get()).BlockType
  of ConsensusFork.Deneb:
    reader.raiseUnexpectedValue($denebImplementationMissing)

proc readValue*[BlockType: ForkedBlindedBeaconBlock](
       reader: var JsonReader[RestJson],
       value: var BlockType
     ) {.raises: [IOError, SerializationError, Defect].} =
  var
    version: Option[ConsensusFork]
    data: Option[JsonString]

  prepareForkedBlockReading(reader, value, version, data,
                            "ForkedBlindedBeaconBlock")

  case version.get():
  of ConsensusFork.Phase0:
    let res =
      try:
        RestJson.decode(string(data.get()),
                        phase0.BeaconBlock,
                        requireAllFields = true,
                        allowUnknownFields = true)
      except SerializationError as exc:
        reader.raiseUnexpectedValue("Incorrect phase0 block format, [" &
                                    exc.formatMsg("BlindedBlock") & "]")
    value = ForkedBlindedBeaconBlock(kind: ConsensusFork.Phase0,
                                     phase0Data: res)
  of ConsensusFork.Altair:
    let res =
      try:
        RestJson.decode(string(data.get()),
                        altair.BeaconBlock,
                        requireAllFields = true,
                        allowUnknownFields = true)
      except SerializationError as exc:
        reader.raiseUnexpectedValue("Incorrect altair block format, [" &
                                    exc.formatMsg("BlindedBlock") & "]")
    value = ForkedBlindedBeaconBlock(kind: ConsensusFork.Altair,
                                     altairData: res)
  of ConsensusFork.Bellatrix:
    let res =
      try:
        RestJson.decode(string(data.get()),
                        bellatrix_mev.BlindedBeaconBlock,
                        requireAllFields = true,
                        allowUnknownFields = true)
      except SerializationError as exc:
        reader.raiseUnexpectedValue("Incorrect bellatrix block format, [" &
                                    exc.formatMsg("BlindedBlock") & "]")
    value = ForkedBlindedBeaconBlock(kind: ConsensusFork.Bellatrix,
                                     bellatrixData: res)
  of ConsensusFork.Capella:
    let res =
      try:
        RestJson.decode(string(data.get()),
                        capella_mev.BlindedBeaconBlock,
                        requireAllFields = true,
                        allowUnknownFields = true)
      except SerializationError as exc:
        reader.raiseUnexpectedValue("Incorrect capella block format, [" &
                                    exc.formatMsg("BlindedBlock") & "]")
    value = ForkedBlindedBeaconBlock(kind: ConsensusFork.Capella,
                                     capellaData: res)
  of ConsensusFork.Deneb:
    reader.raiseUnexpectedValue($denebImplementationMissing)

proc readValue*[BlockType: Web3SignerForkedBeaconBlock](
    reader: var JsonReader[RestJson],
    value: var BlockType) {.raises: [IOError, SerializationError, Defect].} =
  var
    version: Option[ConsensusFork]
    data: Option[JsonString]

  prepareForkedBlockReading(reader, value, version, data,
                            "Web3SignerForkedBeaconBlock")

  case version.get():
  of ConsensusFork.Phase0:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             phase0.BeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[phase0.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect phase0 block format")
    value = Web3SignerForkedBeaconBlock(
      kind: ConsensusFork.Phase0,
      phase0Data: res.get())
  of ConsensusFork.Altair:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             altair.BeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[altair.BeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect altair block format")
    value = Web3SignerForkedBeaconBlock(
      kind: ConsensusFork.Altair,
      altairData: res.get())
  of ConsensusFork.Bellatrix:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             BeaconBlockHeader,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[BeaconBlockHeader]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect bellatrix block format")
    value = Web3SignerForkedBeaconBlock(
      kind: ConsensusFork.Bellatrix,
      bellatrixData: res.get())
  of ConsensusFork.Capella:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             BeaconBlockHeader,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[BeaconBlockHeader]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect capella block format")
    value = Web3SignerForkedBeaconBlock(
      kind: ConsensusFork.Capella,
      capellaData: res.get())
  of ConsensusFork.Deneb:
    reader.raiseUnexpectedValue($denebImplementationMissing)

proc writeValue*[
    BlockType: Web3SignerForkedBeaconBlock](
    writer: var JsonWriter[RestJson],
    value: BlockType) {.raises: [IOError, Defect].} =
  template forkIdentifier(id: string): auto = (static toUpperAscii id)

  # https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing/operation/ETH2_SIGN
  # https://github.com/ConsenSys/web3signer/blob/d51337e96ba5ce410222943556bed7c4856b8e57/core/src/main/java/tech/pegasys/web3signer/core/service/http/handlers/signing/eth2/json/BlockRequestDeserializer.java#L42-L58
  writer.beginRecord()
  case value.kind
  of ConsensusFork.Phase0:
    writer.writeField("version", forkIdentifier "phase0")
    writer.writeField("block", value.phase0Data)
  of ConsensusFork.Altair:
    writer.writeField("version", forkIdentifier "altair")
    writer.writeField("block", value.altairData)
  of ConsensusFork.Bellatrix:
    writer.writeField("version", forkIdentifier "bellatrix")
    writer.writeField("block_header", value.bellatrixData)
  of ConsensusFork.Capella:
    writer.writeField("version", forkIdentifier "capella")
    writer.writeField("block_header", value.capellaData)
  of ConsensusFork.Deneb:
    writer.writeField("version", forkIdentifier "deneb")
    writer.writeField("block_header", value.denebData)
  writer.endRecord()

proc writeValue*[
    BlockType: ForkedBeaconBlock|ForkedBlindedBeaconBlock](
    writer: var JsonWriter[RestJson],
    value: BlockType) {.raises: [IOError, Defect].} =

  template forkIdentifier(id: string): auto =
    when BlockType is ForkedBeaconBlock:
      id
    else:
      (static toUpperAscii id)

  writer.beginRecord()
  case value.kind
  of ConsensusFork.Phase0:
    writer.writeField("version", forkIdentifier "phase0")
    writer.writeField("data", value.phase0Data)
  of ConsensusFork.Altair:
    writer.writeField("version", forkIdentifier "altair")
    writer.writeField("data", value.altairData)
  of ConsensusFork.Bellatrix:
    writer.writeField("version", forkIdentifier "bellatrix")
    writer.writeField("data", value.bellatrixData)
  of ConsensusFork.Capella:
    writer.writeField("version", forkIdentifier "capella")
    writer.writeField("data", value.capellaData)
  of ConsensusFork.Deneb:
    writer.writeField("version", forkIdentifier "deneb")
    writer.writeField("data", value.denebData)
  writer.endRecord()

## RestPublishedBeaconBlockBody
proc readValue*(reader: var JsonReader[RestJson],
                value: var RestPublishedBeaconBlockBody) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    randao_reveal: Option[ValidatorSig]
    eth1_data: Option[Eth1Data]
    graffiti: Option[GraffitiBytes]
    proposer_slashings: Option[
      List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]]
    attester_slashings: Option[
      List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]]
    attestations: Option[List[Attestation, Limit MAX_ATTESTATIONS]]
    deposits: Option[List[Deposit, Limit MAX_DEPOSITS]]
    voluntary_exits: Option[
      List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]]
    sync_aggregate: Option[SyncAggregate]
    execution_payload: Option[RestExecutionPayload]
    bls_to_execution_changes: Option[SignedBLSToExecutionChangeList]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "randao_reveal":
      if randao_reveal.isSome():
        reader.raiseUnexpectedField("Multiple `randao_reveal` fields found",
                                    "RestPublishedBeaconBlockBody")
      randao_reveal = some(reader.readValue(ValidatorSig))
    of "eth1_data":
      if eth1_data.isSome():
        reader.raiseUnexpectedField("Multiple `eth1_data` fields found",
                                    "RestPublishedBeaconBlockBody")
      eth1_data = some(reader.readValue(Eth1Data))
    of "graffiti":
      if graffiti.isSome():
        reader.raiseUnexpectedField("Multiple `graffiti` fields found",
                                    "RestPublishedBeaconBlockBody")
      graffiti = some(reader.readValue(GraffitiBytes))
    of "proposer_slashings":
      if proposer_slashings.isSome():
        reader.raiseUnexpectedField(
          "Multiple `proposer_slashings` fields found",
          "RestPublishedBeaconBlockBody")
      proposer_slashings = some(
        reader.readValue(List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]))
    of "attester_slashings":
      if attester_slashings.isSome():
        reader.raiseUnexpectedField(
          "Multiple `attester_slashings` fields found",
          "RestPublishedBeaconBlockBody")
      attester_slashings = some(
        reader.readValue(List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]))
    of "attestations":
      if attestations.isSome():
        reader.raiseUnexpectedField("Multiple `attestations` fields found",
                                    "RestPublishedBeaconBlockBody")
      attestations = some(
        reader.readValue(List[Attestation, Limit MAX_ATTESTATIONS]))
    of "deposits":
      if deposits.isSome():
        reader.raiseUnexpectedField("Multiple `deposits` fields found",
                                    "RestPublishedBeaconBlockBody")
      deposits = some(reader.readValue(List[Deposit, Limit MAX_DEPOSITS]))
    of "voluntary_exits":
      if voluntary_exits.isSome():
        reader.raiseUnexpectedField("Multiple `voluntary_exits` fields found",
                                    "RestPublishedBeaconBlockBody")
      voluntary_exits = some(
        reader.readValue(List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]))
    of "sync_aggregate":
      if sync_aggregate.isSome():
        reader.raiseUnexpectedField("Multiple `sync_aggregate` fields found",
                                    "RestPublishedBeaconBlockBody")
      sync_aggregate = some(reader.readValue(SyncAggregate))
    of "execution_payload":
      if execution_payload.isSome():
        reader.raiseUnexpectedField("Multiple `execution_payload` fields found",
                                    "RestPublishedBeaconBlockBody")
      execution_payload = some(reader.readValue(RestExecutionPayload))
    of "bls_to_execution_changes":
      if bls_to_execution_changes.isSome():
        reader.raiseUnexpectedField("Multiple `bls_to_execution_changes` fields found",
                                    "RestPublishedBeaconBlockBody")
      bls_to_execution_changes = some(reader.readValue(SignedBLSToExecutionChangeList))
    else:
      unrecognizedFieldWarning()

  if randao_reveal.isNone():
    reader.raiseUnexpectedValue("Field `randao_reveal` is missing")
  if eth1_data.isNone():
    reader.raiseUnexpectedValue("Field `eth1_data` is missing")
  if graffiti.isNone():
    reader.raiseUnexpectedValue("Field `graffiti` is missing")
  if proposer_slashings.isNone():
    reader.raiseUnexpectedValue("Field `proposer_slashings` is missing")
  if attester_slashings.isNone():
    reader.raiseUnexpectedValue("Field `attester_slashings` is missing")
  if attestations.isNone():
    reader.raiseUnexpectedValue("Field `attestations` is missing")
  if deposits.isNone():
    reader.raiseUnexpectedValue("Field `deposits` is missing")
  if voluntary_exits.isNone():
    reader.raiseUnexpectedValue("Field `voluntary_exits` is missing")

  let bodyKind =
    if  execution_payload.isSome() and
        execution_payload.get().withdrawals.isSome() and
        bls_to_execution_changes.isSome() and
        sync_aggregate.isSome():
      ConsensusFork.Capella
    elif execution_payload.isSome() and sync_aggregate.isSome():
      ConsensusFork.Bellatrix
    elif execution_payload.isNone() and sync_aggregate.isSome():
      ConsensusFork.Altair
    else:
      ConsensusFork.Phase0

  template ep_src: auto = execution_payload.get()
  template copy_ep_bellatrix(ep_dst: auto) =
    assign(ep_dst.parent_hash, ep_src.parent_hash)
    assign(ep_dst.fee_recipient, ep_src.fee_recipient)
    assign(ep_dst.state_root, ep_src.state_root)
    assign(ep_dst.receipts_root, ep_src.receipts_root)
    assign(ep_dst.logs_bloom, ep_src.logs_bloom)
    assign(ep_dst.prev_randao, ep_src.prev_randao)
    assign(ep_dst.block_number, ep_src.block_number)
    assign(ep_dst.gas_limit, ep_src.gas_limit)
    assign(ep_dst.gas_used, ep_src.gas_used)
    assign(ep_dst.timestamp, ep_src.timestamp)
    assign(ep_dst.extra_data, ep_src.extra_data)
    assign(ep_dst.base_fee_per_gas, ep_src.base_fee_per_gas)
    assign(ep_dst.block_hash, ep_src.block_hash)
    assign(ep_dst.transactions, ep_src.transactions)

  case bodyKind
  of ConsensusFork.Phase0:
    value = RestPublishedBeaconBlockBody(
      kind: ConsensusFork.Phase0,
      phase0Body: phase0.BeaconBlockBody(
        randao_reveal: randao_reveal.get(),
        eth1_data: eth1_data.get(),
        graffiti: graffiti.get(),
        proposer_slashings: proposer_slashings.get(),
        attester_slashings: attester_slashings.get(),
        attestations: attestations.get(),
        deposits: deposits.get(),
        voluntary_exits: voluntary_exits.get()
      )
    )
  of ConsensusFork.Altair:
    value = RestPublishedBeaconBlockBody(
      kind: ConsensusFork.Altair,
      altairBody: altair.BeaconBlockBody(
        randao_reveal: randao_reveal.get(),
        eth1_data: eth1_data.get(),
        graffiti: graffiti.get(),
        proposer_slashings: proposer_slashings.get(),
        attester_slashings: attester_slashings.get(),
        attestations: attestations.get(),
        deposits: deposits.get(),
        voluntary_exits: voluntary_exits.get(),
        sync_aggregate: sync_aggregate.get()
      )
    )
  of ConsensusFork.Bellatrix:
    value = RestPublishedBeaconBlockBody(
      kind: ConsensusFork.Bellatrix,
      bellatrixBody: bellatrix.BeaconBlockBody(
        randao_reveal: randao_reveal.get(),
        eth1_data: eth1_data.get(),
        graffiti: graffiti.get(),
        proposer_slashings: proposer_slashings.get(),
        attester_slashings: attester_slashings.get(),
        attestations: attestations.get(),
        deposits: deposits.get(),
        voluntary_exits: voluntary_exits.get(),
        sync_aggregate: sync_aggregate.get(),
      )
    )
    copy_ep_bellatrix(value.bellatrixBody.execution_payload)
  of ConsensusFork.Capella:
    value = RestPublishedBeaconBlockBody(
      kind: ConsensusFork.Capella,
      capellaBody: capella.BeaconBlockBody(
        randao_reveal: randao_reveal.get(),
        eth1_data: eth1_data.get(),
        graffiti: graffiti.get(),
        proposer_slashings: proposer_slashings.get(),
        attester_slashings: attester_slashings.get(),
        attestations: attestations.get(),
        deposits: deposits.get(),
        voluntary_exits: voluntary_exits.get(),
        sync_aggregate: sync_aggregate.get(),
        bls_to_execution_changes: bls_to_execution_changes.get()
      )
    )
    copy_ep_bellatrix(value.capellaBody.execution_payload)
    assign(
      value.capellaBody.execution_payload.withdrawals,
      ep_src.withdrawals.get())
  of ConsensusFork.Deneb:
    reader.raiseUnexpectedValue($denebImplementationMissing)

## RestPublishedBeaconBlock
proc readValue*(reader: var JsonReader[RestJson],
                value: var RestPublishedBeaconBlock) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    slot: Option[Slot]
    proposer_index: Option[uint64]
    parent_root: Option[Eth2Digest]
    state_root: Option[Eth2Digest]
    blockBody: Option[RestPublishedBeaconBlockBody]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "slot":
      if slot.isSome():
        reader.raiseUnexpectedField("Multiple `slot` fields found",
                                    "RestPublishedBeaconBlock")
      slot = some(reader.readValue(Slot))
    of "proposer_index":
      if proposer_index.isSome():
        reader.raiseUnexpectedField("Multiple `proposer_index` fields found",
                                    "RestPublishedBeaconBlock")
      proposer_index = some(reader.readValue(uint64))
    of "parent_root":
      if parent_root.isSome():
        reader.raiseUnexpectedField("Multiple `parent_root` fields found",
                                    "RestPublishedBeaconBlock")
      parent_root = some(reader.readValue(Eth2Digest))
    of "state_root":
      if state_root.isSome():
        reader.raiseUnexpectedField("Multiple `state_root` fields found",
                                    "RestPublishedBeaconBlock")
      state_root = some(reader.readValue(Eth2Digest))
    of "body":
      if blockBody.isSome():
        reader.raiseUnexpectedField("Multiple `body` fields found",
                                    "RestPublishedBeaconBlock")
      blockBody = some(reader.readValue(RestPublishedBeaconBlockBody))
    else:
      unrecognizedFieldWarning()

  if slot.isNone():
    reader.raiseUnexpectedValue("Field `slot` is missing")
  if proposer_index.isNone():
    reader.raiseUnexpectedValue("Field `proposer_index` is missing")
  if parent_root.isNone():
    reader.raiseUnexpectedValue("Field `parent_root` is missing")
  if state_root.isNone():
    reader.raiseUnexpectedValue("Field `state_root` is missing")
  if blockBody.isNone():
    reader.raiseUnexpectedValue("Field `body` is missing")

  let body = blockBody.get()
  value = RestPublishedBeaconBlock(
    case body.kind
    of ConsensusFork.Phase0:
      ForkedBeaconBlock.init(
        phase0.BeaconBlock(
          slot: slot.get(),
          proposer_index: proposer_index.get(),
          parent_root: parent_root.get(),
          state_root: state_root.get(),
          body: body.phase0Body
        )
      )
    of ConsensusFork.Altair:
      ForkedBeaconBlock.init(
        altair.BeaconBlock(
          slot: slot.get(),
          proposer_index: proposer_index.get(),
          parent_root: parent_root.get(),
          state_root: state_root.get(),
          body: body.altairBody
        )
      )
    of ConsensusFork.Bellatrix:
      ForkedBeaconBlock.init(
        bellatrix.BeaconBlock(
          slot: slot.get(),
          proposer_index: proposer_index.get(),
          parent_root: parent_root.get(),
          state_root: state_root.get(),
          body: body.bellatrixBody
        )
      )
    of ConsensusFork.Capella:
      ForkedBeaconBlock.init(
        capella.BeaconBlock(
          slot: slot.get(),
          proposer_index: proposer_index.get(),
          parent_root: parent_root.get(),
          state_root: state_root.get(),
          body: body.capellaBody
        )
      )
    of ConsensusFork.Deneb:
      reader.raiseUnexpectedValue($denebImplementationMissing)
  )

## RestPublishedSignedBeaconBlock
proc readValue*(reader: var JsonReader[RestJson],
                value: var RestPublishedSignedBeaconBlock) {.
    raises: [IOError, SerializationError, Defect].} =
  var signature: Option[ValidatorSig]
  var message: Option[RestPublishedBeaconBlock]
  for fieldName in readObjectFields(reader):
    case fieldName
    of "message":
      if message.isSome():
        reader.raiseUnexpectedField("Multiple `message` fields found",
                                    "RestPublishedSignedBeaconBlock")
      message = some(reader.readValue(RestPublishedBeaconBlock))
    of "signature":
      if signature.isSome():
        reader.raiseUnexpectedField("Multiple `signature` fields found",
                                    "RestPublishedSignedBeaconBlock")
      signature = some(reader.readValue(ValidatorSig))
    else:
      unrecognizedFieldWarning()

  if signature.isNone():
    reader.raiseUnexpectedValue("Field `signature` is missing")
  if message.isNone():
    reader.raiseUnexpectedValue("Field `message` is missing")

  let blck = ForkedBeaconBlock(message.get())
  value = RestPublishedSignedBeaconBlock(
    case blck.kind
    of ConsensusFork.Phase0:
      ForkedSignedBeaconBlock.init(
        phase0.SignedBeaconBlock(
          message: blck.phase0Data,
          signature: signature.get()
        )
      )
    of ConsensusFork.Altair:
      ForkedSignedBeaconBlock.init(
        altair.SignedBeaconBlock(
          message: blck.altairData,
          signature: signature.get()
        )
      )
    of ConsensusFork.Bellatrix:
      ForkedSignedBeaconBlock.init(
        bellatrix.SignedBeaconBlock(
          message: blck.bellatrixData,
          signature: signature.get()
        )
      )
    of ConsensusFork.Capella:
      ForkedSignedBeaconBlock.init(
        capella.SignedBeaconBlock(
          message: blck.capellaData,
          signature: signature.get()
        )
      )
    of ConsensusFork.Deneb:
      reader.raiseUnexpectedValue($denebImplementationMissing)
  )

## ForkedSignedBeaconBlock
proc readValue*(reader: var JsonReader[RestJson],
                value: var ForkedSignedBeaconBlock) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    version: Option[ConsensusFork]
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
        version = some(ConsensusFork.Phase0)
      of "altair":
        version = some(ConsensusFork.Altair)
      of "bellatrix":
        version = some(ConsensusFork.Bellatrix)
      of "capella":
        version = some(ConsensusFork.Capella)
      of "deneb":
        version = some(ConsensusFork.Deneb)
      else:
        reader.raiseUnexpectedValue("Incorrect version field value")
    of "data":
      if data.isSome():
        reader.raiseUnexpectedField("Multiple data fields found",
                                    "ForkedSignedBeaconBlock")
      data = some(reader.readValue(JsonString))
    else:
      unrecognizedFieldWarning()

  if version.isNone():
    reader.raiseUnexpectedValue("Field version is missing")
  if data.isNone():
    reader.raiseUnexpectedValue("Field data is missing")

  case version.get():
  of ConsensusFork.Phase0:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             phase0.SignedBeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[phase0.SignedBeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect phase0 block format")
    value = ForkedSignedBeaconBlock.init(res.get())
  of ConsensusFork.Altair:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             altair.SignedBeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[altair.SignedBeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect altair block format")
    value = ForkedSignedBeaconBlock.init(res.get())
  of ConsensusFork.Bellatrix:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             bellatrix.SignedBeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[bellatrix.SignedBeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect bellatrix block format")
    value = ForkedSignedBeaconBlock.init(res.get())
  of ConsensusFork.Capella:
    let res =
      try:
        some(RestJson.decode(string(data.get()),
                             capella.SignedBeaconBlock,
                             requireAllFields = true,
                             allowUnknownFields = true))
      except SerializationError:
        none[capella.SignedBeaconBlock]()
    if res.isNone():
      reader.raiseUnexpectedValue("Incorrect capella block format")
    value = ForkedSignedBeaconBlock.init(res.get())
  of ConsensusFork.Deneb:
    reader.raiseUnexpectedValue($denebImplementationMissing)
  withBlck(value):
    blck.root = hash_tree_root(blck.message)

proc writeValue*(writer: var JsonWriter[RestJson],
                 value: ForkedSignedBeaconBlock) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  case value.kind
  of ConsensusFork.Phase0:
    writer.writeField("version", "phase0")
    writer.writeField("data", value.phase0Data)
  of ConsensusFork.Altair:
    writer.writeField("version", "altair")
    writer.writeField("data", value.altairData)
  of ConsensusFork.Bellatrix:
    writer.writeField("version", "bellatrix")
    writer.writeField("data", value.bellatrixData)
  of ConsensusFork.Capella:
    writer.writeField("version", "capella")
    writer.writeField("data", value.capellaData)
  of ConsensusFork.Deneb:
    writer.writeField("version", "deneb")
    writer.writeField("data", value.denebData)
  writer.endRecord()

# ForkedHashedBeaconState is used where a `ForkedBeaconState` normally would
# be used, mainly because caching the hash early on is easier to do
proc readValue*(reader: var JsonReader[RestJson],
                value: var ForkedHashedBeaconState) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    version: Option[ConsensusFork]
    data: Option[JsonString]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "version":
      if version.isSome():
        reader.raiseUnexpectedField("Multiple version fields found",
                                    "ForkedBeaconState")
      let vres = reader.readValue(string)
      version = case vres
      of "phase0": some(ConsensusFork.Phase0)
      of "altair": some(ConsensusFork.Altair)
      of "bellatrix": some(ConsensusFork.Bellatrix)
      of "capella": some(ConsensusFork.Capella)
      of "deneb": some(ConsensusFork.Deneb)
      else: reader.raiseUnexpectedValue("Incorrect version field value")
    of "data":
      if data.isSome():
        reader.raiseUnexpectedField("Multiple data fields found",
                                    "ForkedBeaconState")
      data = some(reader.readValue(JsonString))
    else:
      unrecognizedFieldWarning()

  if version.isNone():
    reader.raiseUnexpectedValue("Field version is missing")
  if data.isNone():
    reader.raiseUnexpectedValue("Field data is missing")

  # Use a temporary to avoid stack instances and `value` mutation in case of
  # exception
  let
    tmp = (ref ForkedHashedBeaconState)(kind: version.get())

  template toValue(field: untyped) =
    if tmp[].kind == value.kind:
      assign(value.field, tmp[].field)
    else:
      value = tmp[] # slow, but rare (hopefully)
    value.field.root = hash_tree_root(value.field.data)

  case version.get():
  of ConsensusFork.Phase0:
    try:
      tmp[].phase0Data.data = RestJson.decode(
        string(data.get()),
        phase0.BeaconState,
        requireAllFields = true,
        allowUnknownFields = true)
    except SerializationError:
      reader.raiseUnexpectedValue("Incorrect phase0 beacon state format")

    toValue(phase0Data)
  of ConsensusFork.Altair:
    try:
      tmp[].altairData.data = RestJson.decode(
        string(data.get()),
        altair.BeaconState,
        requireAllFields = true,
        allowUnknownFields = true)
    except SerializationError:
      reader.raiseUnexpectedValue("Incorrect altair beacon state format")

    toValue(altairData)
  of ConsensusFork.Bellatrix:
    try:
      tmp[].bellatrixData.data = RestJson.decode(
        string(data.get()),
        bellatrix.BeaconState,
        requireAllFields = true,
        allowUnknownFields = true)
    except SerializationError:
      reader.raiseUnexpectedValue("Incorrect bellatrix beacon state format")
    toValue(bellatrixData)
  of ConsensusFork.Capella:
    try:
      tmp[].capellaData.data = RestJson.decode(
        string(data.get()),
        capella.BeaconState,
        requireAllFields = true,
        allowUnknownFields = true)
    except SerializationError:
      reader.raiseUnexpectedValue("Incorrect capella beacon state format")
    toValue(capellaData)
  of ConsensusFork.Deneb:
    try:
      tmp[].denebData.data = RestJson.decode(
        string(data.get()),
        deneb.BeaconState,
        requireAllFields = true,
        allowUnknownFields = true)
    except SerializationError:
      reader.raiseUnexpectedValue("Incorrect deneb beacon state format")
    toValue(denebData)

proc writeValue*(writer: var JsonWriter[RestJson], value: ForkedHashedBeaconState)
                {.raises: [IOError, Defect].} =
  writer.beginRecord()
  case value.kind
  of ConsensusFork.Phase0:
    writer.writeField("version", "phase0")
    writer.writeField("data", value.phase0Data.data)
  of ConsensusFork.Altair:
    writer.writeField("version", "altair")
    writer.writeField("data", value.altairData.data)
  of ConsensusFork.Bellatrix:
    writer.writeField("version", "bellatrix")
    writer.writeField("data", value.bellatrixData.data)
  of ConsensusFork.Capella:
    writer.writeField("version", "capella")
    writer.writeField("data", value.capellaData.data)
  of ConsensusFork.Deneb:
    writer.writeField("version", "deneb")
    writer.writeField("data", value.denebData.data)
  writer.endRecord()

## Web3SignerRequest
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: Web3SignerRequest) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  case value.kind
  of Web3SignerRequestKind.AggregationSlot:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "AGGREGATION_SLOT")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("aggregation_slot", value.aggregationSlot)
  of Web3SignerRequestKind.AggregateAndProof:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "AGGREGATE_AND_PROOF")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("aggregate_and_proof", value.aggregateAndProof)
  of Web3SignerRequestKind.Attestation:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "ATTESTATION")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("attestation", value.attestation)
  of Web3SignerRequestKind.Block:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "BLOCK")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("block", value.blck)
  of Web3SignerRequestKind.BlockV2:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "BLOCK_V2")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)

    # https://github.com/ConsenSys/web3signer/blob/41c0cbfabcb1fca9587b59e058b7eb29f152c60c/core/src/main/resources/openapi-specs/eth2/signing/schemas.yaml#L418-L497
    writer.writeField("beacon_block", value.beaconBlock)

  of Web3SignerRequestKind.Deposit:
    writer.writeField("type", "DEPOSIT")
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("deposit", value.deposit)
  of Web3SignerRequestKind.RandaoReveal:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "RANDAO_REVEAL")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("randao_reveal", value.randaoReveal)
  of Web3SignerRequestKind.VoluntaryExit:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "VOLUNTARY_EXIT")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("voluntary_exit", value.voluntaryExit)
  of Web3SignerRequestKind.SyncCommitteeMessage:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "SYNC_COMMITTEE_MESSAGE")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("sync_committee_message", value.syncCommitteeMessage)
  of Web3SignerRequestKind.SyncCommitteeSelectionProof:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "SYNC_COMMITTEE_SELECTION_PROOF")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("sync_aggregator_selection_data",
                      value.syncAggregatorSelectionData)
  of Web3SignerRequestKind.SyncCommitteeContributionAndProof:
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("contribution_and_proof",
                      value.syncCommitteeContributionAndProof)
  of Web3SignerRequestKind.ValidatorRegistration:
    # https://consensys.github.io/web3signer/web3signer-eth2.html#operation/ETH2_SIGN
    doAssert(value.forkInfo.isSome(),
             "forkInfo should be set for this type of request")
    writer.writeField("type", "VALIDATOR_REGISTRATION")
    writer.writeField("fork_info", value.forkInfo.get())
    if isSome(value.signingRoot):
      writer.writeField("signingRoot", value.signingRoot)
    writer.writeField("validator_registration", value.validatorRegistration)
  writer.endRecord()

proc readValue*(reader: var JsonReader[RestJson],
                value: var Web3SignerRequest) {.
     raises: [IOError, SerializationError, Defect].} =
  var
    requestKind: Option[Web3SignerRequestKind]
    forkInfo: Option[Web3SignerForkInfo]
    signingRoot: Option[Eth2Digest]
    data: Option[JsonString]
    dataName: string

  for fieldName in readObjectFields(reader):
    case fieldName
    of "type":
      if requestKind.isSome():
        reader.raiseUnexpectedField("Multiple `type` fields found",
                                    "Web3SignerRequest")
      let vres = reader.readValue(string)
      requestKind = some(
        case vres
        of "AGGREGATION_SLOT":
          Web3SignerRequestKind.AggregationSlot
        of "AGGREGATE_AND_PROOF":
          Web3SignerRequestKind.AggregateAndProof
        of "ATTESTATION":
          Web3SignerRequestKind.Attestation
        of "BLOCK":
          Web3SignerRequestKind.Block
        of "BLOCK_V2":
          Web3SignerRequestKind.BlockV2
        of "DEPOSIT":
          Web3SignerRequestKind.Deposit
        of "RANDAO_REVEAL":
          Web3SignerRequestKind.RandaoReveal
        of "VOLUNTARY_EXIT":
          Web3SignerRequestKind.VoluntaryExit
        of "SYNC_COMMITTEE_MESSAGE":
          Web3SignerRequestKind.SyncCommitteeMessage
        of "SYNC_COMMITTEE_SELECTION_PROOF":
          Web3SignerRequestKind.SyncCommitteeSelectionProof
        of "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF":
          Web3SignerRequestKind.SyncCommitteeContributionAndProof
        of "VALIDATOR_REGISTRATION":
          Web3SignerRequestKind.ValidatorRegistration
        else:
          reader.raiseUnexpectedValue("Unexpected `type` value")
      )
    of "fork_info":
      if forkInfo.isSome():
        reader.raiseUnexpectedField("Multiple `fork_info` fields found",
                                    "Web3SignerRequest")
      forkInfo = some(reader.readValue(Web3SignerForkInfo))
    of "signingRoot":
      if signingRoot.isSome():
        reader.raiseUnexpectedField("Multiple `signingRoot` fields found",
                                    "Web3SignerRequest")
      signingRoot = some(reader.readValue(Eth2Digest))
    of "aggregation_slot", "aggregate_and_proof", "block", "beacon_block",
       "randao_reveal", "voluntary_exit", "sync_committee_message",
       "sync_aggregator_selection_data", "contribution_and_proof", "attestation":
      if data.isSome():
        reader.raiseUnexpectedField("Multiple data fields found",
                                    "Web3SignerRequest")
      dataName = fieldName
      data = some(reader.readValue(JsonString))
    else:
      unrecognizedFieldWarning()

  if requestKind.isNone():
    reader.raiseUnexpectedValue("Field `type` is missing")

  value =
    case requestKind.get()
    of Web3SignerRequestKind.AggregationSlot:
      if dataName != "aggregation_slot":
        reader.raiseUnexpectedValue("Field `aggregation_slot` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(Web3SignerAggregationSlotData, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `aggregation_slot` format")
          res.get()
      Web3SignerRequest(kind: Web3SignerRequestKind.AggregationSlot,
        forkInfo: forkInfo, signingRoot: signingRoot, aggregationSlot: data
      )
    of Web3SignerRequestKind.AggregateAndProof:
      if dataName != "aggregate_and_proof":
        reader.raiseUnexpectedValue("Field `aggregate_and_proof` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(AggregateAndProof, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `aggregate_and_proof` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.AggregateAndProof,
        forkInfo: forkInfo, signingRoot: signingRoot, aggregateAndProof: data
      )
    of Web3SignerRequestKind.Attestation:
      if dataName != "attestation":
        reader.raiseUnexpectedValue("Field `attestation` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(AttestationData, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `attestation` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.Attestation,
        forkInfo: forkInfo, signingRoot: signingRoot, attestation: data
      )
    of Web3SignerRequestKind.Block:
      if dataName != "block":
        reader.raiseUnexpectedValue("Field `block` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(phase0.BeaconBlock, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `block` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.Block,
        forkInfo: forkInfo, signingRoot: signingRoot, blck: data
      )
    of Web3SignerRequestKind.BlockV2:
      # https://github.com/ConsenSys/web3signer/blob/41834a927088f1bde7a097e17d19e954d0058e54/core/src/main/resources/openapi-specs/eth2/signing/schemas.yaml#L421-L425 (branch v22.7.0)
      # It's the "beacon_block" field even when it's not a block, but a header
      if dataName != "beacon_block":
        reader.raiseUnexpectedValue("Field `beacon_block` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(Web3SignerForkedBeaconBlock, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `beacon_block` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.BlockV2,
        forkInfo: forkInfo, signingRoot: signingRoot, beaconBlock: data
      )
    of Web3SignerRequestKind.Deposit:
      if dataName != "deposit":
        reader.raiseUnexpectedValue("Field `deposit` is missing")
      let data =
        block:
          let res = decodeJsonString(Web3SignerDepositData, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `deposit` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.Deposit,
        signingRoot: signingRoot, deposit: data
      )
    of Web3SignerRequestKind.RandaoReveal:
      if dataName != "randao_reveal":
        reader.raiseUnexpectedValue("Field `randao_reveal` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(Web3SignerRandaoRevealData, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `randao_reveal` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.RandaoReveal,
        forkInfo: forkInfo, signingRoot: signingRoot, randaoReveal: data
      )
    of Web3SignerRequestKind.VoluntaryExit:
      if dataName != "voluntary_exit":
        reader.raiseUnexpectedValue("Field `voluntary_exit` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(VoluntaryExit, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `voluntary_exit` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.VoluntaryExit,
        forkInfo: forkInfo, signingRoot: signingRoot, voluntaryExit: data
      )
    of Web3SignerRequestKind.SyncCommitteeMessage:
      if dataName != "sync_committee_message":
        reader.raiseUnexpectedValue(
          "Field `sync_committee_message` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(Web3SignerSyncCommitteeMessageData, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `sync_committee_message` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.SyncCommitteeMessage,
        forkInfo: forkInfo, signingRoot: signingRoot,
        syncCommitteeMessage: data
      )
    of Web3SignerRequestKind.SyncCommitteeSelectionProof:
      if dataName != "sync_aggregator_selection_data":
        reader.raiseUnexpectedValue(
          "Field `sync_aggregator_selection_data` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(SyncAggregatorSelectionData, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `sync_aggregator_selection_data` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.SyncCommitteeSelectionProof,
        forkInfo: forkInfo, signingRoot: signingRoot,
        syncAggregatorSelectionData: data
      )
    of Web3SignerRequestKind.SyncCommitteeContributionAndProof:
      if dataName != "contribution_and_proof":
        reader.raiseUnexpectedValue(
          "Field `contribution_and_proof` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res = decodeJsonString(ContributionAndProof, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `contribution_and_proof` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.SyncCommitteeContributionAndProof,
        forkInfo: forkInfo, signingRoot: signingRoot,
        syncCommitteeContributionAndProof: data
      )
    of Web3SignerRequestKind.ValidatorRegistration:
      if dataName != "validator_registration":
        reader.raiseUnexpectedValue(
          "Field `validator_registration` is missing")
      if forkInfo.isNone():
        reader.raiseUnexpectedValue("Field `fork_info` is missing")
      let data =
        block:
          let res =
            decodeJsonString(Web3SignerValidatorRegistration, data.get())
          if res.isErr():
            reader.raiseUnexpectedValue(
              "Incorrect field `validator_registration` format")
          res.get()
      Web3SignerRequest(
        kind: Web3SignerRequestKind.ValidatorRegistration,
        forkInfo: forkInfo, signingRoot: signingRoot,
        validatorRegistration: data
      )

## RemoteKeystoreStatus
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: RemoteKeystoreStatus) {.raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("status", $value.status)
  if value.message.isSome():
    writer.writeField("message", value.message.get())
  writer.endRecord()

proc readValue*(reader: var JsonReader[RestJson],
                value: var RemoteKeystoreStatus) {.
     raises: [IOError, SerializationError, Defect].} =
  var message: Option[string]
  var status: Option[KeystoreStatus]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "message":
      if message.isSome():
        reader.raiseUnexpectedField("Multiple `message` fields found",
                                    "RemoteKeystoreStatus")
      message = some(reader.readValue(string))
    of "status":
      if status.isSome():
        reader.raiseUnexpectedField("Multiple `status` fields found",
                                    "RemoteKeystoreStatus")
      let res = reader.readValue(string)
      status = some(
        case res
        of "error":
          KeystoreStatus.error
        of "not_active":
          KeystoreStatus.notActive
        of "not_found":
          KeystoreStatus.notFound
        of "deleted":
          KeystoreStatus.deleted
        of "duplicate":
          KeystoreStatus.duplicate
        of "imported":
          KeystoreStatus.imported
        else:
          reader.raiseUnexpectedValue("Invalid `status` value")
      )
    else:
      unrecognizedFieldWarning()

  if status.isNone():
    reader.raiseUnexpectedValue("Field `status` is missing")

  value = RemoteKeystoreStatus(status: status.get(), message: message)

## ScryptSalt
proc readValue*(reader: var JsonReader[RestJson], value: var ScryptSalt) {.
     raises: [SerializationError, IOError, Defect].} =
  let res = ncrutils.fromHex(reader.readValue(string))
  if len(res) == 0:
    reader.raiseUnexpectedValue("Invalid scrypt salt value")
  value = ScryptSalt(res)

## Pbkdf2Params
proc writeValue*(writer: var JsonWriter[RestJson], value: Pbkdf2Params) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("dklen", JsonString(Base10.toString(value.dklen)))
  writer.writeField("c", JsonString(Base10.toString(value.c)))
  writer.writeField("prf", value.prf)
  writer.writeField("salt", value.salt)
  writer.endRecord()

proc readValue*(reader: var JsonReader[RestJson], value: var Pbkdf2Params) {.
     raises: [SerializationError, IOError, Defect].} =
  var
    dklen: Option[uint64]
    c: Option[uint64]
    prf: Option[PrfKind]
    salt: Option[Pbkdf2Salt]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "dklen":
      if dklen.isSome():
        reader.raiseUnexpectedField("Multiple `dklen` fields found",
                                    "Pbkdf2Params")
      dklen = some(reader.readValue(uint64))
    of "c":
      if c.isSome():
        reader.raiseUnexpectedField("Multiple `c` fields found",
                                    "Pbkdf2Params")
      c = some(reader.readValue(uint64))
    of "prf":
      if prf.isSome():
        reader.raiseUnexpectedField("Multiple `prf` fields found",
                                    "Pbkdf2Params")
      prf = some(reader.readValue(PrfKind))
    of "salt":
      if salt.isSome():
        reader.raiseUnexpectedField("Multiple `salt` fields found",
                                    "Pbkdf2Params")
      salt = some(reader.readValue(Pbkdf2Salt))
    else:
      unrecognizedFieldWarning()

  if dklen.isNone():
    reader.raiseUnexpectedValue("Field `dklen` is missing")
  if c.isNone():
    reader.raiseUnexpectedValue("Field `c` is missing")
  if prf.isNone():
    reader.raiseUnexpectedValue("Field `prf` is missing")
  if salt.isNone():
    reader.raiseUnexpectedValue("Field `salt` is missing")

  value = Pbkdf2Params(
    dklen: dklen.get(),
    c: c.get(),
    prf: prf.get(),
    salt: salt.get()
  )

## ScryptParams
proc writeValue*(writer: var JsonWriter[RestJson], value: ScryptParams) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("dklen", JsonString(Base10.toString(value.dklen)))
  writer.writeField("n", JsonString(Base10.toString(uint64(value.n))))
  writer.writeField("p", JsonString(Base10.toString(uint64(value.p))))
  writer.writeField("r", JsonString(Base10.toString(uint64(value.r))))
  writer.writeField("salt", value.salt)
  writer.endRecord()

proc readValue*(reader: var JsonReader[RestJson], value: var ScryptParams) {.
     raises: [SerializationError, IOError, Defect].} =
  var
    dklen: Option[uint64]
    n, p, r: Option[int]
    salt: Option[ScryptSalt]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "dklen":
      if dklen.isSome():
        reader.raiseUnexpectedField("Multiple `dklen` fields found",
                                    "ScryptParams")
      dklen = some(reader.readValue(uint64))
    of "n":
      if n.isSome():
        reader.raiseUnexpectedField("Multiple `n` fields found",
                                    "ScryptParams")
      let res = reader.readValue(int)
      if res < 0:
        reader.raiseUnexpectedValue("Unexpected negative `n` value")
      n = some(res)
    of "p":
      if p.isSome():
        reader.raiseUnexpectedField("Multiple `p` fields found",
                                    "ScryptParams")
      let res = reader.readValue(int)
      if res < 0:
        reader.raiseUnexpectedValue("Unexpected negative `p` value")
      p = some(res)
    of "r":
      if r.isSome():
        reader.raiseUnexpectedField("Multiple `r` fields found",
                                    "ScryptParams")
      let res = reader.readValue(int)
      if res < 0:
        reader.raiseUnexpectedValue("Unexpected negative `r` value")
      r = some(res)
    of "salt":
      if salt.isSome():
        reader.raiseUnexpectedField("Multiple `salt` fields found",
                                    "ScryptParams")
      salt = some(reader.readValue(ScryptSalt))
    else:
      unrecognizedFieldWarning()

  if dklen.isNone():
    reader.raiseUnexpectedValue("Field `dklen` is missing")
  if n.isNone():
    reader.raiseUnexpectedValue("Field `n` is missing")
  if p.isNone():
    reader.raiseUnexpectedValue("Field `p` is missing")
  if r.isNone():
    reader.raiseUnexpectedValue("Field `r` is missing")
  if salt.isNone():
    reader.raiseUnexpectedValue("Field `salt` is missing")

  value = ScryptParams(
    dklen: dklen.get(),
    n: n.get(), p: p.get(), r: r.get(),
    salt: salt.get()
  )

## Keystore
proc writeValue*(writer: var JsonWriter[RestJson], value: Keystore) {.
     error: "keystores must be converted to json with Json.encode(keystore). " &
            "There is no REST-specific encoding" .}

proc readValue*(reader: var JsonReader[RestJson], value: var Keystore) {.
     error: "Keystores must be loaded with `parseKeystore`. " &
            "There is no REST-specific encoding".}

## KeystoresAndSlashingProtection
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: KeystoresAndSlashingProtection) {.
     raises: [IOError, SerializationError, Defect].} =
  writer.beginRecord()
  let keystores =
    block:
      var res: seq[string]
      for keystore in value.keystores:
        let encoded = Json.encode(keystore)
        res.add(encoded)
      res
  writer.writeField("keystores", keystores)
  writer.writeField("passwords", value.passwords)
  if value.slashing_protection.isSome():
    let slashingProtection = RestJson.encode(value.slashing_protection.get)
    writer.writeField("slashing_protection", slashingProtection)
  writer.endRecord()

proc readValue*(reader: var JsonReader[RestJson],
                value: var KeystoresAndSlashingProtection) {.
     raises: [SerializationError, IOError, Defect].} =
  var
    strKeystores: seq[string]
    passwords: seq[string]
    strSlashing: Option[string]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "keystores":
      strKeystores = reader.readValue(seq[string])
    of "passwords":
      passwords = reader.readValue(seq[string])
    of "slashing_protection":
      if strSlashing.isSome():
        reader.raiseUnexpectedField(
          "Multiple `slashing_protection` fields found",
          "KeystoresAndSlashingProtection")
      strSlashing = some(reader.readValue(string))
    else:
      unrecognizedFieldWarning()

  if len(strKeystores) == 0:
    reader.raiseUnexpectedValue("Missing or empty `keystores` value")
  if len(passwords) == 0:
    reader.raiseUnexpectedValue("Missing or empty `passwords` value")

  let keystores =
    block:
      var res: seq[Keystore]
      for item in strKeystores:
        let key =
          try:
            parseKeystore(item)
          except SerializationError as exc:
            # TODO re-raise the exception by adjusting the column index, so the user
            # will get an accurate syntax error within the larger message
            reader.raiseUnexpectedValue("Invalid keystore format")
        res.add(key)
      res

  let slashing =
    if strSlashing.isSome():
      let db =
        try:
          RestJson.decode(strSlashing.get(),
                          SPDIR,
                          requireAllFields = true,
                          allowUnknownFields = true)
        except SerializationError as exc:
          reader.raiseUnexpectedValue("Invalid slashing protection format")
      some(db)
    else:
      none[SPDIR]()

  value = KeystoresAndSlashingProtection(
    keystores: keystores, passwords: passwords, slashing_protection: slashing
  )

## RestActivityItem
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: RestActivityItem) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("index", value.index)
  writer.writeField("epoch", value.epoch)
  writer.writeField("active", value.active)
  writer.endRecord()

proc readValue*(reader: var JsonReader[RestJson],
                value: var RestActivityItem) {.
     raises: [SerializationError, IOError, Defect].} =
  var index: Option[ValidatorIndex]
  var epoch: Option[Epoch]
  var active: Option[bool]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "index":
      if index.isSome():
        reader.raiseUnexpectedField(
          "Multiple `index` fields found", "RestActivityItem")
      index = some(reader.readValue(ValidatorIndex))
    of "epoch":
      if epoch.isSome():
        reader.raiseUnexpectedField(
          "Multiple `epoch` fields found", "RestActivityItem")
      epoch = some(reader.readValue(Epoch))
    of "active":
      if active.isSome():
        reader.raiseUnexpectedField(
          "Multiple `active` fields found", "RestActivityItem")
      active = some(reader.readValue(bool))
    else:
      discard

  if index.isNone():
    reader.raiseUnexpectedValue("Missing or empty `index` value")
  if epoch.isNone():
    reader.raiseUnexpectedValue("Missing or empty `epoch` value")
  if active.isNone():
    reader.raiseUnexpectedValue("Missing or empty `active` value")

  value = RestActivityItem(index: index.get(), epoch: epoch.get(),
                           active: active.get())

## RestLivenessItem
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: RestLivenessItem) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("index", value.index)
  writer.writeField("is_live", value.is_live)
  writer.endRecord()

proc readValue*(reader: var JsonReader[RestJson],
                value: var RestLivenessItem) {.
     raises: [SerializationError, IOError, Defect].} =
  var index: Option[ValidatorIndex]
  var isLive: Option[bool]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "index":
      if index.isSome():
        reader.raiseUnexpectedField(
          "Multiple `index` fields found", "RestLivenessItem")
      index = some(reader.readValue(ValidatorIndex))
    of "is_live":
      if isLive.isSome():
        reader.raiseUnexpectedField(
          "Multiple `is_live` fields found", "RestLivenessItem")
      isLive = some(reader.readValue(bool))
    else:
      discard

  if index.isNone():
    reader.raiseUnexpectedValue("Missing or empty `index` value")
  if isLive.isNone():
    reader.raiseUnexpectedValue("Missing or empty `is_live` value")

  value = RestLivenessItem(index: index.get(), is_live: isLive.get())

## HeadChangeInfoObject
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: HeadChangeInfoObject) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("slot", value.slot)
  writer.writeField("block", value.block_root)
  writer.writeField("state", value.state_root)
  writer.writeField("epoch_transition", value.epoch_transition)
  writer.writeField("previous_duty_dependent_root",
                    value.previous_duty_dependent_root)
  writer.writeField("current_duty_dependent_root",
                    value.current_duty_dependent_root)
  if value.optimistic.isSome():
    writer.writeField("execution_optimistic", value.optimistic.get())
  writer.endRecord()

## ReorgInfoObject
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: ReorgInfoObject) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("slot", value.slot)
  writer.writeField("depth", value.depth)
  writer.writeField("old_head_block", value.old_head_block)
  writer.writeField("new_head_block", value.new_head_block)
  writer.writeField("old_head_state", value.old_head_state)
  writer.writeField("new_head_state", value.new_head_state)
  if value.optimistic.isSome():
    writer.writeField("execution_optimistic", value.optimistic.get())
  writer.endRecord()

## FinalizationInfoObject
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: FinalizationInfoObject) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("block", value.block_root)
  writer.writeField("state", value.state_root)
  writer.writeField("epoch", value.epoch)
  if value.optimistic.isSome():
    writer.writeField("execution_optimistic", value.optimistic.get())
  writer.endRecord()

## EventBeaconBlockObject
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: EventBeaconBlockObject) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("slot", value.slot)
  writer.writeField("block", value.block_root)
  if value.optimistic.isSome():
    writer.writeField("execution_optimistic", value.optimistic.get())
  writer.endRecord()

## RestSyncInfo
proc writeValue*(writer: var JsonWriter[RestJson],
                 value: RestSyncInfo) {.
     raises: [IOError, Defect].} =
  writer.beginRecord()
  writer.writeField("head_slot", value.head_slot)
  writer.writeField("sync_distance", value.sync_distance)
  writer.writeField("is_syncing", value.is_syncing)
  if value.is_optimistic.isSome():
    writer.writeField("is_optimistic", value.is_optimistic.get())
  writer.endRecord()

## RestErrorMessage
proc readValue*(reader: var JsonReader[RestJson],
                value: var RestErrorMessage) {.
     raises: [SerializationError, IOError, Defect].} =
  var
    code: Opt[int]
    message: Opt[string]
    stacktraces: Option[seq[string]]

  for fieldName in readObjectFields(reader):
    case fieldName
    of "code":
      if code.isSome():
        reader.raiseUnexpectedField("Multiple `code` fields found",
                                    "RestErrorMessage")
      let ires =
        try:
          let res = reader.readValue(int)
          if res < 0:
            reader.raiseUnexpectedValue("Invalid `code` field value")
          Opt.some(res)
        except SerializationError:
          Opt.none(int)
      if ires.isNone():
        let sres =
          try: parseInt(reader.readValue(string))
          except ValueError:
            reader.raiseUnexpectedValue("Invalid `code` field format")
        if sres < 0:
          reader.raiseUnexpectedValue("Invalid `code` field value")
        code = Opt.some(sres)
      else:
        code = ires
    of "message":
      if message.isSome():
        reader.raiseUnexpectedField("Multiple `message` fields found",
                                    "RestErrorMessage")
      message = Opt.some(reader.readValue(string))
    of "stacktraces":
      if stacktraces.isSome():
        reader.raiseUnexpectedField("Multiple `stacktraces` fields found",
                                    "RestErrorMessage")
      stacktraces = some(reader.readValue(seq[string]))
    else:
      # We ignore all additional fields.
      discard reader.readValue(JsonString)

  if code.isNone():
    reader.raiseUnexpectedValue("Missing or invalid `code` value")
  if message.isNone():
    reader.raiseUnexpectedValue("Missing or invalid `message` value")

  value = RestErrorMessage(
    code: code.get(), message: message.get(),
    stacktraces: stacktraces
  )

proc parseRoot(value: string): Result[Eth2Digest, cstring] =
  try:
    ok(Eth2Digest(data: hexToByteArray[32](value)))
  except ValueError:
    err("Unable to decode root value")

proc decodeBody*(
       t: typedesc[RestPublishedSignedBeaconBlock],
       body: ContentBody,
       version: string
     ): Result[RestPublishedSignedBeaconBlock, cstring] =
  if body.contentType == ApplicationJsonMediaType:
    let data =
      try:
        RestJson.decode(body.data, RestPublishedSignedBeaconBlock,
                        requireAllFields = true,
                        allowUnknownFields = true)
      except SerializationError as exc:
        debug "Failed to deserialize REST JSON data",
              err = exc.formatMsg("<data>"),
              data = string.fromBytes(body.data)
        return err("Unable to deserialize data")
      except CatchableError:
        return err("Unexpected deserialization error")
    ok(data)
  elif body.contentType == OctetStreamMediaType:
    let consensusFork = ? ConsensusFork.decodeString(version)
    case consensusFork
    of ConsensusFork.Phase0:
      let blck =
        try:
          SSZ.decode(body.data, phase0.SignedBeaconBlock)
        except SerializationError:
          return err("Unable to deserialize data")
        except CatchableError:
          return err("Unexpected deserialization error")
      ok(RestPublishedSignedBeaconBlock(ForkedSignedBeaconBlock.init(blck)))
    of ConsensusFork.Altair:
      let blck =
        try:
          SSZ.decode(body.data, altair.SignedBeaconBlock)
        except SerializationError:
          return err("Unable to deserialize data")
        except CatchableError:
          return err("Unexpected deserialization error")
      ok(RestPublishedSignedBeaconBlock(ForkedSignedBeaconBlock.init(blck)))
    of ConsensusFork.Bellatrix:
      let blck =
        try:
          SSZ.decode(body.data, bellatrix.SignedBeaconBlock)
        except SerializationError:
          return err("Unable to deserialize data")
        except CatchableError:
          return err("Unexpected deserialization error")
      ok(RestPublishedSignedBeaconBlock(ForkedSignedBeaconBlock.init(blck)))
    of ConsensusFork.Capella:
      let blck =
        try:
          SSZ.decode(body.data, capella.SignedBeaconBlock)
        except SerializationError:
          return err("Unable to deserialize data")
        except CatchableError:
          return err("Unexpected deserialization error")
      ok(RestPublishedSignedBeaconBlock(ForkedSignedBeaconBlock.init(blck)))
    of ConsensusFork.Deneb:
      return err($denebImplementationMissing)
  else:
    return err("Unsupported or invalid content media type")

proc decodeBody*[T](t: typedesc[T],
                    body: ContentBody): Result[T, cstring] =
  if body.contentType != ApplicationJsonMediaType:
    return err("Unsupported content type")
  let data =
    try:
      RestJson.decode(body.data, T,
                      requireAllFields = true,
                      allowUnknownFields = true)
    except SerializationError as exc:
      debug "Failed to deserialize REST JSON data",
            err = exc.formatMsg("<data>"),
            data = string.fromBytes(body.data)
      return err("Unable to deserialize data")
    except CatchableError:
      return err("Unexpected deserialization error")
  ok(data)

proc decodeBodyJsonOrSsz*[T](t: typedesc[T],
                             body: ContentBody): Result[T, cstring] =
  if body.contentType == ApplicationJsonMediaType:
    let data =
      try:
        RestJson.decode(body.data, T,
                        requireAllFields = true,
                        allowUnknownFields = true)
      except SerializationError as exc:
        debug "Failed to deserialize REST JSON data",
              err = exc.formatMsg("<data>"),
              data = string.fromBytes(body.data)
        return err("Unable to deserialize data")
      except CatchableError:
        return err("Unexpected deserialization error")
    ok(data)
  elif body.contentType == OctetStreamMediaType:
    let blck =
      try:
        SSZ.decode(body.data, T)
      except SerializationError:
        return err("Unable to deserialize data")
      except CatchableError:
        return err("Unexpected deserialization error")
    ok(blck)
  else:
    return err("Unsupported content type")

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

proc encodeBytes*[T: EncodeOctetTypes](
       value: T,
       contentType: string
     ): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    let data =
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
  of "application/octet-stream":
    let data =
      try:
        SSZ.encode(value)
      except CatchableError:
        return err("Serialization error")
    ok(data)
  else:
    err("Content-Type not supported")

proc decodeBytes*[T: DecodeTypes](
       t: typedesc[T],
       value: openArray[byte],
       contentType: Opt[ContentTypeData]
     ): RestResult[T] =

  let mediaType =
    if contentType.isNone():
      ApplicationJsonMediaType
    else:
      if isWildCard(contentType.get().mediaType):
        return err("Incorrect Content-Type")
      contentType.get().mediaType

  if mediaType == ApplicationJsonMediaType:
    try:
      ok RestJson.decode(value, T,
                         requireAllFields = true,
                         allowUnknownFields = true)
    except SerializationError as exc:
      debug "Failed to deserialize REST JSON data",
            err = exc.formatMsg("<data>"),
            data = string.fromBytes(value)
      err("Serialization error")
  else:
    err("Content-Type not supported")

proc encodeString*(value: string): RestResult[string] =
  ok(value)

proc encodeString*(value: Epoch|Slot|CommitteeIndex|SyncSubcommitteeIndex): RestResult[string] =
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

proc encodeString*(value: ValidatorPubKey): RestResult[string] =
  ok(hexOriginal(toRaw(value)))

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

proc encodeString*(peerid: PeerId): Result[string, cstring] =
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
  of "contribution_and_proof":
    ok(EventTopic.ContributionAndProof)
  of "light_client_finality_update":
    ok(EventTopic.LightClientFinalityUpdate)
  of "light_client_optimistic_update":
    ok(EventTopic.LightClientOptimisticUpdate)
  else:
    err("Incorrect event's topic value")

proc decodeString*(t: typedesc[ValidatorSig],
                   value: string): Result[ValidatorSig, cstring] =
  if len(value) != ValidatorSigSize + 2:
    return err("Incorrect validator signature value length")
  if value[0] != '0' and value[1] != 'x':
    return err("Incorrect validator signature encoding")
  ValidatorSig.fromHex(value)

proc decodeString*(t: typedesc[ValidatorPubKey],
                   value: string): Result[ValidatorPubKey, cstring] =
  if len(value) != ValidatorKeySize + 2:
    return err("Incorrect validator's key value length")
  if value[0] != '0' and value[1] != 'x':
    err("Incorrect validator's key encoding")
  else:
    ValidatorPubKey.fromHex(value)

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

proc decodeString*(t: typedesc[SyncCommitteePeriod],
                   value: string): Result[SyncCommitteePeriod, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(SyncCommitteePeriod(res))

proc decodeString*(t: typedesc[uint64],
                   value: string): Result[uint64, cstring] =
  Base10.decode(uint64, value)

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

proc decodeString*(t: typedesc[PeerId],
                   value: string): Result[PeerId, cstring] =
  PeerId.init(value)

proc decodeString*(t: typedesc[CommitteeIndex],
                   value: string): Result[CommitteeIndex, cstring] =
  let res = ? Base10.decode(uint64, value)
  CommitteeIndex.init(res)

proc decodeString*(t: typedesc[SyncSubcommitteeIndex],
                   value: string): Result[SyncSubcommitteeIndex, cstring] =
  let res = ? Base10.decode(uint64, value)
  SyncSubcommitteeIndex.init(res)

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

proc decodeString*(t: typedesc[ConsensusFork],
                   value: string): Result[ConsensusFork, cstring] =
  case toLowerAscii(value)
  of "phase0": ok(ConsensusFork.Phase0)
  of "altair": ok(ConsensusFork.Altair)
  of "bellatrix": ok(ConsensusFork.Bellatrix)
  of "capella": ok(ConsensusFork.Capella)
  of "deneb": ok(ConsensusFork.Deneb)
  else: err("Unsupported or invalid beacon block fork version")
