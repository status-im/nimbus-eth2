# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/[json, strutils],
  stew/[base10, byteutils],
  libp2p/peerid,
  presto/common as presto_common,
  ../eth2_ssz_serialization,
  ./eth2_rest_json_serialization

export peerid, presto_common, eth2_ssz_serialization, eth2_rest_json_serialization

func decodeMediaType*(
    contentType: Opt[ContentTypeData]): Result[MediaType, string] =
  if contentType.isNone or isWildCard(contentType.get.mediaType):
    return err("Missing or incorrect Content-Type")
  ok contentType.get.mediaType

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
  UnableDecodeVersionError = "Unable to decode version"
  UnableDecodeError = "Unable to decode data"
  InvalidContentTypeError* = "Invalid content type"
  UnexpectedForkVersionError* = "Unexpected fork version received"

type
  EncodeTypes* =
    BlobSidecarInfoObject |
    DataColumnSidecarInfoObject |
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
    phase0.AttesterSlashing |
    SignedValidatorRegistrationV1 |
    SignedVoluntaryExit |
    Web3SignerRequest |
    RestNimbusTimestamp1 |
    SetGraffitiRequest

  EncodeOctetTypes* =
    altair.SignedBeaconBlock |
    bellatrix.SignedBeaconBlock |
    capella.SignedBeaconBlock |
    phase0.SignedBeaconBlock |
    DenebSignedBlockContents |
    ElectraSignedBlockContents |
    FuluSignedBlockContents |
    GloasSignedBlockContents |
    HezeSignedBlockContents |
    ForkedMaybeBlindedBeaconBlock |
    deneb_mev.SignedBlindedBeaconBlock |
    electra_mev.SignedBlindedBeaconBlock |
    fulu_mev.SignedBlindedBeaconBlock

  EncodeArrays* =
    seq[phase0.Attestation] |
    seq[electra.SingleAttestation] |
    seq[PrepareBeaconProposer] |
    seq[RemoteKeystoreInfo] |
    seq[RestCommitteeSubscription] |
    seq[RestSignedContributionAndProof] |
    seq[RestSyncCommitteeMessage] |
    seq[RestSyncCommitteeSubscription] |
    seq[phase0.SignedAggregateAndProof] |
    seq[electra.SignedAggregateAndProof] |
    seq[SignedValidatorRegistrationV1] |
    seq[ValidatorIndex] |
    seq[RestBeaconCommitteeSelection] |
    seq[RestSyncCommitteeSelection]

  MevDecodeTypes* =
    GetHeaderResponseFulu

  DecodeTypes* =
    DataEnclosedObject |
    DataMetaEnclosedObject |
    DataRootEnclosedObject |
    DataOptimisticObject |
    DataVersionEnclosedObject |
    DataOptimisticAndFinalizedObject |
    GetBlockV2Response |
    GetDistributedKeystoresResponse |
    GetHistoricalSummariesV1Response |
    GetHistoricalSummariesV1ResponseElectra |
    GetKeystoresResponse |
    GetRemoteKeystoresResponse |
    GetStateForkResponse |
    GetStateV2Response |
    KeymanagerGenericError |
    KeystoresAndSlashingProtection |
    ListFeeRecipientResponse |
    PrepareBeaconProposer |
    RestIndexedErrorMessage |
    RestErrorMessage |
    RestValidator |
    Web3SignerErrorResponse |
    Web3SignerKeysResponse |
    Web3SignerSignatureResponse |
    Web3SignerStatusResponse |
    GetStateRootResponse |
    GetBlockRootResponse |
    SomeForkedLightClientObject |
    seq[SomeForkedLightClientObject] |
    RestNimbusTimestamp1 |
    RestNimbusTimestamp2 |
    GetGraffitiResponse |
    GetAggregatedAttestationV2Response

  RestVersioned*[T] = object
    data*: T
    jsonVersion*: ConsensusFork
    sszContext*: ForkDigest

  RestBlockTypes* = phase0.BeaconBlock | altair.BeaconBlock |
                    bellatrix.BeaconBlock | capella.BeaconBlock |
                    deneb.BlockContents | electra.BlockContents |
                    fulu.BlockContents | electra_mev.BlindedBeaconBlock |
                    fulu_mev.BlindedBeaconBlock

func ethHeaders(
    consensusFork: ConsensusFork,
    hasRestAllowedOrigin: bool): HttpTable =
  var headers = HttpTable.init [
    ("eth-consensus-version", consensusFork.toString())]
  if hasRestAllowedOrigin:
    headers.add("access-control-expose-headers", "eth-consensus-version")
  headers

func ethHeaders(
    consensusFork: ConsensusFork,
    isBlinded: bool,
    executionValue: UInt256,
    consensusValue: UInt256,
    hasRestAllowedOrigin: bool): HttpTable =
  var headers = HttpTable.init [
    ("eth-consensus-version", consensusFork.toString()),
    ("eth-execution-payload-blinded", if isBlinded: "true" else: "false"),
    ("eth-execution-payload-value", toString(executionValue, 10)),
    ("eth-consensus-block-value", toString(consensusValue, 10))]
  if hasRestAllowedOrigin:
    headers.add("access-control-expose-headers", static(
      "eth-consensus-version, eth-execution-payload-blinded, " &
      "eth-execution-payload-value, eth-consensus-block-value"))
  headers

func readStrictHexChar(c: char, radix: static[uint8]): Result[int8, cstring] =
  ## Converts an hex char to an int
  const
    lowerLastChar = chr(ord('a') + radix - 11'u8)
    capitalLastChar = chr(ord('A') + radix - 11'u8)
  case c
  of '0' .. '9': ok(int8 ord(c) - ord('0'))
  of 'a' .. lowerLastChar: ok(int8 ord(c) - ord('a') + 10)
  of 'A' .. capitalLastChar: ok(int8 ord(c) - ord('A') + 10)
  else: err("Invalid hexadecimal character encountered!")

func readStrictDecChar(c: char, radix: static[uint8]): Result[int8, cstring] =
  const lastChar = char(ord('0') + radix - 1'u8)
  case c
  of '0' .. lastChar: ok(int8 ord(c) - ord('0'))
  else: err("Invalid decimal character encountered!")

func skipPrefixes(str: string,
                  radix: range[2..16]): Result[int, cstring] =
  ## Returns the index of the first meaningful char in `hexStr` by skipping
  ## "0x" prefix
  if len(str) < 2:
    return ok(0)

  return
    if str[0] == '0':
      if str[1] in {'x', 'X'}:
        if radix != 16:
          return err("Parsing mismatch, 0x prefix is only valid for a " &
                     "hexadecimal number (base 16)")
        ok(2)
      elif str[1] in {'o', 'O'}:
        if radix != 8:
          return err("Parsing mismatch, 0o prefix is only valid for an " &
                     "octal number (base 8)")
        ok(2)
      elif str[1] in {'b', 'B'}:
        if radix == 2:
          ok(2)
        elif radix == 16:
          # allow something like "0bcdef12345" which is a valid hex
          ok(0)
        else:
          err("Parsing mismatch, 0b prefix is only valid for a binary number " &
              "(base 2), or hex number")
      else:
        ok(0)
    else:
      ok(0)

func strictParse*[bits: static[int]](input: string,
                                     T: typedesc[StUint[bits]],
                                     radix: static[uint8] = 10
                                    ): Result[T, cstring] {.raises: [].} =
  var res: T
  static: doAssert (radix >= 2) and (radix <= 16),
            "Only base from 2..16 are supported"

  const
    base = radix.uint8.stuint(bits)
    zero = 0.uint8.stuint(256)

  var currentIndex =
    block:
      let res = skipPrefixes(input, radix)
      if res.isErr():
        return err(res.error)
      res.get()

  while currentIndex < len(input):
    let value =
      when radix <= 10:
        ? readStrictDecChar(input[currentIndex], radix)
      else:
        ? readStrictHexChar(input[currentIndex], radix)
    let mres = res * base
    if (res != zero) and (mres div base != res):
      return err("Overflow error")
    let ares = mres + value.stuint(bits)
    if ares < mres:
      return err("Overflow error")
    res = ares
    inc(currentIndex)
  ok(res)

template withRestJsonWriter(w, typ, body: untyped): untyped =
  try:
    var stream = memoryOutput()
    var w = JsonWriter[RestJson].init(stream)
    body
    stream.getOutput(typ)
  except IOError:
    raiseAssert "No IOError from memoryOutput"

proc prepareJsonResponse*(_: typedesc[RestApiResponse], d: auto): seq[byte] =
  withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("data", d)

proc prepareJsonStringResponse*[T: SomeForkedLightClientObject](
    _: typedesc[RestApiResponse], d: RestVersioned[T]): string =
  withForkyObject(d.data):
    when lcDataFork > LightClientDataFork.None:
      withRestJsonWriter(w, string):
        w.writeObject:
          w.writeField("version", d.jsonVersion.toString())
          w.writeField("data", forkyObject)
    else:
      default(string)

proc prepareJsonStringResponse*(_: typedesc[RestApiResponse], d: auto): string =
  RestJson.encode(d)

proc jsonResponseWRoot*(_: typedesc[RestApiResponse], data: auto,
                        dependent_root: Eth2Digest,
                        execOpt: Opt[bool]): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("dependent_root", dependent_root)
      w.writeField("execution_optimistic", execOpt)
      w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponse*(_: typedesc[RestApiResponse], data: auto): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponseBlock*(
    _: typedesc[RestApiResponse],
    data: ForkySignedBlindedBeaconBlock,
    execOpt: Opt[bool],
    finalized: bool,
    consensusFork: ConsensusFork,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    headers = consensusFork.ethHeaders(hasRestAllowedOrigin)
    res = withRestJsonWriter(w, seq[byte]):
      w.writeObject:
        w.writeField("version", consensusFork)
        w.writeField("execution_optimistic", execOpt)
        w.writeField("finalized", finalized)
        w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseBlock*(
    _: typedesc[RestApiResponse],
    data: ForkedSignedBeaconBlock,
    execOpt: Opt[bool],
    finalized: bool,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    headers = data.kind.ethHeaders(hasRestAllowedOrigin)
    res = withRestJsonWriter(w, seq[byte]):
      w.writeObject:
        w.writeField("version", data.kind)
        w.writeField("execution_optimistic", execOpt)
        w.writeField("finalized", finalized)
        withBlck(data):
          w.writeField("data", forkyBlck)

  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseState*(
    _: typedesc[RestApiResponse],
    data: ForkedHashedBeaconState,
    execOpt: Opt[bool],
    finalized: bool,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    headers = data.kind.ethHeaders(hasRestAllowedOrigin)
    res = withRestJsonWriter(w, seq[byte]):
      w.writeObject:
        w.writeField("version", data.kind)
        w.writeField("execution_optimistic", execOpt)
        w.writeField("finalized", finalized)
        withState(data):
          w.writeField("data", forkyState.data)

  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseWOpt*(_: typedesc[RestApiResponse], data: auto,
                       execOpt: Opt[bool]): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("execution_optimistic", execOpt)
      w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json")

proc prepareJsonResponseFinalized*(
    _: typedesc[RestApiResponse], data: auto, exec: Opt[bool],
    finalized: bool
): seq[byte] =
  withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("execution_optimistic", exec)
      w.writeField("finalized", finalized)
      w.writeField("data", data)

proc jsonResponseFinalized*(_: typedesc[RestApiResponse], data: auto,
                            exec: Opt[bool],
                            finalized: bool): RestApiResponse =
  let res = RestApiResponse.prepareJsonResponseFinalized(data, exec, finalized)
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponseFinalizedWVersion*(
    _: typedesc[RestApiResponse],
    data: auto,
    exec: Opt[bool],
    finalized: bool,
    version: ConsensusFork,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    headers = version.ethHeaders(hasRestAllowedOrigin)
    res = withRestJsonWriter(w, seq[byte]):
      w.writeObject:
        w.writeField("version", version)
        w.writeField("execution_optimistic", exec)
        w.writeField("finalized", finalized)
        w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseWVersion*(
    _: typedesc[RestApiResponse],
    data: auto,
    version: ConsensusFork,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    headers = version.ethHeaders(hasRestAllowedOrigin)
    res = withRestJsonWriter(w, seq[byte]):
      w.writeObject:
        w.writeField("version", version)
        w.writeField("data", data)

  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseVersioned*[T: SomeForkedLightClientObject](
    _: typedesc[RestApiResponse],
    entries: openArray[RestVersioned[T]]): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
      for e in w.stepwiseArrayCreation(entries):
        withForkyObject(e.data):
          when lcDataFork > LightClientDataFork.None:
            w.writeObject:
              w.writeField("version", e.jsonVersion.toString())
              w.writeField("data", forkyObject)

  RestApiResponse.response(res, Http200, "application/json")

proc jsonPlainEncoded(data: auto): seq[byte] =
  withRestJsonWriter(w, seq[byte]):
    w.writeValue(data)

proc jsonResponsePlain*(_: typedesc[RestApiResponse],
                        data: auto): RestApiResponse =
  let res = data.jsonPlainEncoded()
  RestApiResponse.response(res, Http200, "application/json")

proc jsonResponsePlain*(
    _: typedesc[RestApiResponse],
    data: auto,
    consensusFork: ConsensusFork,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = data.jsonPlainEncoded()
    headers = consensusFork.ethHeaders(hasRestAllowedOrigin)
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponsePlain*(
    _: typedesc[RestApiResponse],
    data: auto,
    consensusFork: ConsensusFork,
    isBlinded: bool,
    executionValue: UInt256,
    consensusValue: UInt256,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = data.jsonPlainEncoded()
    headers = consensusFork.ethHeaders(
      isBlinded, executionValue, consensusValue, hasRestAllowedOrigin)
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseWMeta*(_: typedesc[RestApiResponse],
                        data: auto, meta: auto): RestApiResponse =
  let res = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("data", data)
      w.writeField("meta", meta)

  RestApiResponse.response(res, Http200, "application/json")

proc jsonMsgResponse*(_: typedesc[RestApiResponse],
                      msg: string = ""): RestApiResponse =
  let data = withRestJsonWriter(w, seq[byte]):
    w.writeObject:
      w.writeField("code", 200)
      w.writeField("message", msg)

  RestApiResponse.response(data, Http200, "application/json")

proc jsonError*(_: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = ""): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)

  RestApiResponse.error(status, data, "application/json")

proc jsonError*(_: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "", stacktrace: string): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)
      if len(stacktrace) > 0:
        w.writeField("stacktraces", [stacktrace])

  RestApiResponse.error(status, data, "application/json")

proc jsonError*(_: typedesc[RestApiResponse], status: HttpCode = Http200,
                msg: string = "",
                stacktraces: openArray[string]): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)
      w.writeField("stacktraces", stacktraces)

  RestApiResponse.error(status, data, "application/json")

proc jsonError*(_: typedesc[RestApiResponse],
                rmsg: RestErrorMessage): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", rmsg.code)
      w.writeField("message", rmsg.message)
      w.writeField("stacktraces", rmsg.stacktraces)

  RestApiResponse.error(rmsg.code.toHttpCode().get(), data, "application/json")

proc jsonErrorList*(_: typedesc[RestApiResponse],
                    status: HttpCode = Http200,
                    msg: string = "", failures: auto): RestApiResponse =
  let data = withRestJsonWriter(w, string):
    w.writeObject:
      w.writeField("code", int(status.toInt()))
      w.writeField("message", msg)
      w.writeField("failures", failures)

  RestApiResponse.error(status, data, "application/json")

proc sszResponseVersioned*[T: SomeForkedLightClientObject](
    _: typedesc[RestApiResponse],
    entries: openArray[RestVersioned[T]]): RestApiResponse =
  let res =
    try:
      var stream = memoryOutput()
      for e in entries:
        withForkyUpdate(e.data):
          when lcDataFork > LightClientDataFork.None:
            var cursor = stream.delayFixedSizeWrite(sizeof(uint64))
            let initPos = stream.pos
            stream.write e.sszContext.data
            var w = SszWriter.init(stream)
            w.writeValue forkyUpdate
            cursor.finalWrite (stream.pos - initPos).uint64.toBytesLE()
      stream.getOutput(seq[byte])
    except IOError:
      default(seq[byte])
  RestApiResponse.response(res, Http200, "application/octet-stream")

proc sszResponsePlain*(
    _: typedesc[RestApiResponse],
    res: seq[byte],
    consensusFork: ConsensusFork,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let headers = consensusFork.ethHeaders(hasRestAllowedOrigin)
  RestApiResponse.response(
    res, Http200, "application/octet-stream", headers = headers)

proc sszResponse*(
    _: typedesc[RestApiResponse],
    data: auto,
    consensusFork: ConsensusFork,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = SSZ.encode(data)
    headers = consensusFork.ethHeaders(hasRestAllowedOrigin)
  RestApiResponse.response(
    res, Http200, "application/octet-stream", headers = headers)

proc sszResponse*(
    _: typedesc[RestApiResponse],
    data: auto,
    consensusFork: ConsensusFork,
    isBlinded: bool,
    executionValue: UInt256,
    consensusValue: UInt256,
    hasRestAllowedOrigin: bool): RestApiResponse =
  let
    res = SSZ.encode(data)
    headers = consensusFork.ethHeaders(
      isBlinded, executionValue, consensusValue, hasRestAllowedOrigin)
  RestApiResponse.response(
    res, Http200, "application/octet-stream", headers = headers)

proc parseRoot(value: string): Result[Eth2Digest, cstring] =
  try:
    ok(Eth2Digest(data: hexToByteArray[32](value)))
  except ValueError:
    err("Unable to decode root value")

proc decodeBody*(
       _: typedesc[RestPublishedSignedBlockContents],
       body: ContentBody,
       version: string
     ): Result[RestPublishedSignedBlockContents, RestErrorMessage] =
  if body.contentType == ApplicationJsonMediaType:
    let consensusFork = ConsensusFork.decodeString(version).valueOr:
      return err(RestErrorMessage.init(Http400, UnableDecodeVersionError,
                                       [version, $error]))

    try:
      var res = RestPublishedSignedBlockContents(kind: consensusFork)
      withForkyBlck(res):
        forkyData = RestJson.decode(body.data, typeof(forkyData))
      ok res
    except SerializationError as exc:
      debug "Failed to decode JSON data",
        err = exc.formatMsg("<data>"), data = string.fromBytes(body.data)
      err RestErrorMessage.init(
        Http400, UnableDecodeError, [version, exc.formatMsg("<data>")]
      )
  elif body.contentType == OctetStreamMediaType:
    let consensusFork = ConsensusFork.decodeString(version).valueOr:
      return err(RestErrorMessage.init(Http400, UnableDecodeVersionError,
                                       [version, $error]))
    try:
      var res = RestPublishedSignedBlockContents(kind: consensusFork)
      withForkyBlck(res):
        forkyData = SSZ.decode(body.data, typeof(forkyData))
      ok res
    except SerializationError as exc:
      err RestErrorMessage.init(
        Http400, UnableDecodeError, [version, exc.formatMsg("<data>")]
      )
  else:
    err(RestErrorMessage.init(Http415, InvalidContentTypeError,
                              [version, $body.contentType]))

proc decodeBodyJsonOrSsz*(
    t: typedesc[seq[SignedValidatorRegistrationV1]],
    body: ContentBody
): Result[seq[SignedValidatorRegistrationV1], RestErrorMessage] =
  if body.contentType == ApplicationJsonMediaType:
    let data =
      try:
        RestJson.decode(
          body.data,
          seq[SignedValidatorRegistrationV1])
      except SerializationError as exc:
        debug "Failed to deserialize REST JSON data",
              err = exc.formatMsg("<data>")
        return err(
          RestErrorMessage.init(Http400, UnableDecodeError,
                                [exc.formatMsg("<data>")]))
    ok(data)
  elif body.contentType == OctetStreamMediaType:
    let data =
      try:
        SSZ.decode(
          body.data,
          List[SignedValidatorRegistrationV1, Limit VALIDATOR_REGISTRY_LIMIT])
      except SerializationError as exc:
        debug "Failed to deserialize REST SSZ data",
              err = exc.formatMsg("<data>")
        return err(
          RestErrorMessage.init(Http400, UnableDecodeError,
                                [exc.formatMsg("<data>")]))
    ok(data.asSeq)
  else:
    err(RestErrorMessage.init(Http415, InvalidContentTypeError,
                              [$body.contentType]))

proc decodeBytesJsonOrSsz*(
    T: typedesc[MevDecodeTypes],
    data: openArray[byte],
    contentType: Opt[ContentTypeData],
    version: string
): Result[T, RestErrorMessage] =
  var res: T
  const typeFork = kind(typeof(res.data))

  if contentType == ApplicationJsonMediaType:
    res =
      try:
        RestJson.decode(data, T)
      except SerializationError as exc:
        debug "Failed to deserialize REST JSON data",
              err = exc.formatMsg("<data>")
        return err(
          RestErrorMessage.init(Http400, UnableDecodeError,
                                [exc.formatMsg("<data>")]))
    let jsonFork = ConsensusFork.decodeString(res.version.getStr()).valueOr:
      return err(RestErrorMessage.init(Http400, UnableDecodeVersionError,
                                       [res.version.getStr(), $error]))
    if typeFork != jsonFork:
      return err(
        RestErrorMessage.init(Http400, UnexpectedForkVersionError,
                              ["json-version", res.version.getStr(),
                               typeFork.toString()]))
    ok(res)
  elif contentType == OctetStreamMediaType:
    let consensusFork =
      ConsensusFork.decodeString(version).valueOr:
        return err(RestErrorMessage.init(Http400, UnableDecodeVersionError,
                                         [version, $error]))
    if typeFork != consensusFork:
      return err(
        RestErrorMessage.init(
          Http400, UnexpectedForkVersionError,
          ["eth-consensus-version", consensusFork.toString(),
           typeFork.toString()]))

    ok(T(
      version: newJString(typeFork.toString()),
      data:
        try:
          SSZ.decode(data, typeof(res.data))
        except SerializationError as exc:
          return err(
            RestErrorMessage.init(Http400, UnableDecodeError,
                                  [exc.formatMsg("<data>")]))))
  else:
    err(RestErrorMessage.init(Http415, InvalidContentTypeError,
                              [$contentType]))

proc decodeBody*(T: typedesc, body: ContentBody): Result[T, cstring] =
  if body.contentType != ApplicationJsonMediaType:
    return err("Unsupported content type")

  try:
    ok RestJson.decode(body.data, T)
  except SerializationError as exc:
    debug "Failed to deserialize REST JSON data",
          err = exc.formatMsg("<data>"),
          data = string.fromBytes(body.data)
    err("Unable to deserialize data")

proc decodeBodyJsonOrSsz*(T: typedesc,
                          body: ContentBody): Result[T, RestErrorMessage] =
  if body.contentType == ApplicationJsonMediaType:
    try:
      ok RestJson.decode(body.data, T)
    except SerializationError as exc:
      debug "Failed to decode JSON data",
            err = exc.formatMsg("<data>"),
            data = string.fromBytes(body.data)
      err(RestErrorMessage.init(Http400, UnableDecodeError,
                                [exc.formatMsg("<data>")]))
  elif body.contentType == OctetStreamMediaType:
    try:
      ok SSZ.decode(body.data, T)
    except SerializationError as exc:
      err(RestErrorMessage.init(Http400, UnableDecodeError,
                                [exc.formatMsg("<data>")]))
  else:
    err(RestErrorMessage.init(Http415, InvalidContentTypeError,
                              [$body.contentType]))

proc encodeBytes*(value: seq[SignedValidatorRegistrationV1],
                  contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    ok block:
      withRestJsonWriter(w, seq[byte]):
        w.writeArray(value)
  of "application/octet-stream":
    ok(SSZ.encode(
      init(
        List[SignedValidatorRegistrationV1, Limit VALIDATOR_REGISTRY_LIMIT],
        value)))
  else:
    err("Content-Type not supported")

proc encodeBytes*[T: EncodeTypes](value: T,
                                  contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    ok block:
      withRestJsonWriter(w, seq[byte]):
        w.writeValue(value)
  else:
    err("Content-Type not supported")

proc encodeBytes*[T: EncodeArrays](value: T,
                                   contentType: string): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    ok block:
      withRestJsonWriter(w, seq[byte]):
        w.writeArray(value)
  else:
    err("Content-Type not supported")

proc encodeBytes*[T: EncodeOctetTypes](
    value: T,
    contentType: string
): RestResult[seq[byte]] =
  case contentType
  of "application/json":
    ok block:
      withRestJsonWriter(w, seq[byte]):
        w.writeValue(value)
  of "application/octet-stream":
    ok(SSZ.encode(value))
  else:
    err("Content-Type not supported")

func readSszResBytes(T: typedesc[RestBlockTypes],
                     data: openArray[byte]): RestResult[T] =
  var res: T
  try:
    readSszBytes(data, res)
    ok(res)
  except SszSizeMismatchError:
    err("Incorrect SSZ object's size")
  except SszError:
    err("Invalid SSZ object")

proc decodeBytes*[T: ProduceBlockResponseV3](
    t: typedesc[T],
    value: openArray[byte],
    contentType: Opt[ContentTypeData],
    headerConsensusVersion: string,
    headerBlinded: string,
    headerPayloadValue: string,
    headerConsensusValue: string): RestResult[T] =
  let
    mediaType =
      if contentType.isNone():
        ApplicationJsonMediaType
      else:
        if isWildCard(contentType.get().mediaType):
          return err("Incorrect Content-Type")
        contentType.get().mediaType

  if mediaType == ApplicationJsonMediaType:
    try:
      ok(RestJson.decode(value, T))
    except SerializationError as exc:
      debug "Failed to deserialize REST JSON data",
            err = exc.formatMsg("<data>"),
            data = string.fromBytes(value)
      return err("Serialization error")
  elif mediaType == OctetStreamMediaType:
    let
      fork = ConsensusFork.decodeString(headerConsensusVersion).valueOr:
        return err("Invalid or Unsupported consensus version")
      blinded =
        block:
          var toCheck = headerBlinded.toLowerAscii()
          if toCheck == "true":
            true
          elif toCheck == "false":
            false
          else:
            return err("Incorrect `Eth-Execution-Payload-Blinded` header value")
      executionValue =
        try:
          Opt.some parse(headerPayloadValue, UInt256, 10)
        except ValueError:
          return err("Incorrect `Eth-Execution-Payload-Value` header value")
      consensusValue =
        if len(headerConsensusValue) == 0:
          # TODO (cheatfate): We should not allow empty `consensus-value`.
          Opt.none(UInt256)
        else:
          try:
            Opt.some parse(headerConsensusValue, UInt256, 10)
          except ValueError:
            return err("Incorrect `Eth-Consensus-Block-Value` header value")
    withConsensusFork(fork):
      debugGloasComment ""
      when consensusFork == ConsensusFork.Gloas:
        return err("gloas produceblock not available yet")
      elif consensusFork == ConsensusFork.Heze:
        return err("heze produceblock not available yet")
      elif consensusFork >= ConsensusFork.Fulu:
        if blinded:
          let contents =
            ? readSszResBytes(consensusFork.BlindedBlockContents, value)
          ok(
            ForkedMaybeBlindedBeaconBlock.init(
              contents, executionValue, consensusValue))
        else:
          let contents = ? readSszResBytes(consensusFork.BlockContents, value)
          ok(
            ForkedMaybeBlindedBeaconBlock.init(
              contents, executionValue, consensusValue))
      elif consensusFork >= ConsensusFork.Bellatrix:
        if blinded:
          return err("`Eth-Execution-Payload-Blinded` unsupported for " &
                     "`Eth-Consensus-Version`")
        let contents = ? readSszResBytes(consensusFork.BlockContents, value)
        ok(
          ForkedMaybeBlindedBeaconBlock.init(
            contents, executionValue, consensusValue))
      else:
        if blinded:
          return err("`Eth-Execution-Payload-Blinded` unsupported for " &
                     "`Eth-Consensus-Version`")
        let contents = ? readSszResBytes(consensusFork.BlockContents, value)
        ok(ForkedMaybeBlindedBeaconBlock.init(contents))
  else:
    err("Unsupported Content-Type")

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
      ok RestJson.decode(value, T)
    except SerializationError as exc:
      debug "Failed to deserialize REST JSON data",
            err = exc.formatMsg("<data>"),
            data = string.fromBytes(value)
      err("Serialization error")
  else:
    err("Content-Type not supported")

func encodeString*(value: string): RestResult[string] =
  ok(value)

func encodeString*(
    value:
      uint64 |
      SyncCommitteePeriod |
      Epoch |
      Slot |
      CommitteeIndex |
      SyncSubcommitteeIndex): RestResult[string] =
  ok(Base10.toString(uint64(value)))

func encodeString*(value: ValidatorSig): RestResult[string] =
  ok(to0xHex(toRaw(value)))

func encodeString*(value: GraffitiBytes): RestResult[string] =
  ok(to0xHex(distinctBase(value)))

func encodeString*(value: Eth2Digest): RestResult[string] =
  ok(to0xHex(value.data))

func encodeString*(value: ValidatorIdent): RestResult[string] =
  case value.kind
  of ValidatorQueryKind.Index:
    ok(Base10.toString(uint64(value.index)))
  of ValidatorQueryKind.Key:
    ok(to0xHex(toRaw(value.key)))

func encodeString*(value: ValidatorPubKey): RestResult[string] =
  ok(to0xHex(toRaw(value)))

func encodeString*(value: StateIdent): RestResult[string] =
  case value.kind
  of StateQueryKind.Slot:
    ok(Base10.toString(uint64(value.slot)))
  of StateQueryKind.Root:
    ok(to0xHex(value.root.data))
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

func encodeString*(value: BroadcastValidationType): RestResult[string] =
  case value
  of BroadcastValidationType.Gossip:
    ok("gossip")
  of BroadcastValidationType.Consensus:
    ok("consensus")
  of BroadcastValidationType.ConsensusAndEquivocation:
    ok("consensus_and_equivocation")

func encodeString*(value: BlockIdent): RestResult[string] =
  case value.kind
  of BlockQueryKind.Slot:
    ok(Base10.toString(uint64(value.slot)))
  of BlockQueryKind.Root:
    ok(to0xHex(value.root.data))
  of BlockQueryKind.Named:
    case value.value
    of BlockIdentType.Head:
      ok("head")
    of BlockIdentType.Genesis:
      ok("genesis")
    of BlockIdentType.Finalized:
      ok("finalized")

func decodeString*(t: typedesc[PeerStateKind],
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
    err("Incorrect peer state value")

func encodeString*(value: PeerStateKind): Result[string, cstring] =
  case value
  of PeerStateKind.Disconnected:
    ok("disconnected")
  of PeerStateKind.Connecting:
    ok("connecting")
  of PeerStateKind.Connected:
    ok("connected")
  of PeerStateKind.Disconnecting:
    ok("disconnecting")

func decodeString*(t: typedesc[PeerDirectKind],
                   value: string): Result[PeerDirectKind, cstring] =
  case value
  of "inbound":
    ok(PeerDirectKind.Inbound)
  of "outbound":
    ok(PeerDirectKind.Outbound)
  else:
    err("Incorrect peer direction value")

func encodeString*(value: PeerDirectKind): Result[string, cstring] =
  case value
  of PeerDirectKind.Inbound:
    ok("inbound")
  of PeerDirectKind.Outbound:
    ok("outbound")

func encodeString*(peerid: PeerId): Result[string, cstring] =
  ok($peerid)

func decodeString*(t: typedesc[EventTopic],
                   value: string): Result[EventTopic, cstring] =
  case value
  of "head":
    ok(EventTopic.Head)
  of "block":
    ok(EventTopic.Block)
  of "block_gossip":
    ok(EventTopic.BlockGossip)
  of "single_attestation":
    ok(EventTopic.SingleAttestation)
  of "voluntary_exit":
    ok(EventTopic.VoluntaryExit)
  of "bls_to_execution_change":
    ok(EventTopic.BLSToExecutionChange)
  of "proposer_slashing":
    ok(EventTopic.ProposerSlashing)
  of "attester_slashing":
    ok(EventTopic.AttesterSlashing)
  of "blob_sidecar":
    ok(EventTopic.BlobSidecar)
  of "data_column_sidecar":
    ok(EventTopic.DataColumnSidecar)
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
  of "execution_payload":
    ok(EventTopic.ExecutionPayloadAdded)
  of "execution_payload_gossip":
    ok(EventTopic.ExecutionPayloadGossipAdded)
  of "execution_payload_available":
    ok(EventTopic.ExecutionPayloadAvailable)
  of "execution_payload_bid":
    ok(EventTopic.ExecutionPayloadBid)
  of "payload_attestation_message":
    ok(EventTopic.PayloadAttestationMessage)
  of "fast_confirmation":
    ok(EventTopic.FastConfirmation)
  else:
    err("Incorrect event's topic value")

func encodeString*(value: set[EventTopic]): Result[string, cstring] =
  var res: string
  if EventTopic.Head in value:
    res.add("head,")
  if EventTopic.Block in value:
    res.add("block,")
  if EventTopic.BlockGossip in value:
    res.add("block_gossip,")
  if EventTopic.SingleAttestation in value:
    res.add("single_attestation,")
  if EventTopic.VoluntaryExit in value:
    res.add("voluntary_exit,")
  if EventTopic.BLSToExecutionChange in value:
    res.add("bls_to_execution_change,")
  if EventTopic.ProposerSlashing in value:
    res.add("proposer_slashing,")
  if EventTopic.AttesterSlashing in value:
    res.add("attester_slashing,")
  if EventTopic.BlobSidecar in value:
    res.add("blob_sidecar,")
  if EventTopic.DataColumnSidecar in value:
    res.add("data_column_sidecar,")
  if EventTopic.FinalizedCheckpoint in value:
    res.add("finalized_checkpoint,")
  if EventTopic.ChainReorg in value:
    res.add("chain_reorg,")
  if EventTopic.ContributionAndProof in value:
    res.add("contribution_and_proof,")
  if EventTopic.LightClientFinalityUpdate in value:
    res.add("light_client_finality_update,")
  if EventTopic.LightClientOptimisticUpdate in value:
    res.add("light_client_optimistic_update,")
  if EventTopic.ExecutionPayloadAdded in value:
    res.add("execution_payload,")
  if EventTopic.ExecutionPayloadGossipAdded in value:
    res.add("execution_payload_gossip,")
  if EventTopic.ExecutionPayloadAvailable in value:
    res.add("execution_payload_available,")
  if EventTopic.ExecutionPayloadBid in value:
    res.add("execution_payload_bid,")
  if EventTopic.PayloadAttestationMessage in value:
    res.add("payload_attestation_message,")
  if len(res) == 0:
    return err("Topics set must not be empty")
  res.setLen(len(res) - 1)
  ok(res)

func decodeString*(t: typedesc[ValidatorSig],
                   value: string): Result[ValidatorSig, cstring] =
  if len(value) != ValidatorSigSize + 2:
    return err("Incorrect validator signature value length")
  if value[0] != '0' and value[1] != 'x':
    return err("Incorrect validator signature encoding")
  ValidatorSig.fromHex(value)

func decodeString*(t: typedesc[ValidatorPubKey],
                   value: string): Result[ValidatorPubKey, cstring] =
  if len(value) != ValidatorKeySize + 2:
    return err("Incorrect validator's key value length")
  if value[0] != '0' and value[1] != 'x':
    err("Incorrect validator's key encoding")
  else:
    ValidatorPubKey.fromHex(value)

func decodeString*(t: typedesc[GraffitiBytes],
                   value: string): Result[GraffitiBytes, cstring] =
  try:
    ok(GraffitiBytes.init(value))
  except ValueError:
    err("Unable to decode graffiti value")

func decodeString*(t: typedesc[string],
                   value: string): Result[string, cstring] =
  ok(value)

func decodeString*(t: typedesc[Slot], value: string): Result[Slot, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(Slot(res))

func decodeString*(t: typedesc[Epoch], value: string): Result[Epoch, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(Epoch(res))

func decodeString*(t: typedesc[SyncCommitteePeriod],
                   value: string): Result[SyncCommitteePeriod, cstring] =
  let res = ? Base10.decode(uint64, value)
  ok(SyncCommitteePeriod(res))

func decodeString*(t: typedesc[uint64],
                   value: string): Result[uint64, cstring] =
  Base10.decode(uint64, value)

func decodeString*(t: typedesc[StateIdent],
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

func decodeString*(t: typedesc[BlockIdent],
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

func decodeString*(t: typedesc[BroadcastValidationType],
                   value: string): Result[BroadcastValidationType, cstring] =
  case value
  of "gossip":
    ok(BroadcastValidationType.Gossip)
  of "consensus":
    ok(BroadcastValidationType.Consensus)
  of "consensus_and_equivocation":
    ok(BroadcastValidationType.ConsensusAndEquivocation)
  else:
    err("Incorrect broadcast validation type value")

func decodeString*(t: typedesc[ValidatorIdent],
                   value: string): Result[ValidatorIdent, cstring] =
  ValidatorIdent.parse(value)

func decodeString*(t: typedesc[PeerId],
                   value: string): Result[PeerId, cstring] =
  PeerId.init(value)

func decodeString*(t: typedesc[CommitteeIndex],
                   value: string): Result[CommitteeIndex, cstring] =
  let res = ? Base10.decode(uint64, value)
  CommitteeIndex.init(res)

func decodeString*(t: typedesc[SyncSubcommitteeIndex],
                   value: string): Result[SyncSubcommitteeIndex, cstring] =
  let res = ? Base10.decode(uint64, value)
  SyncSubcommitteeIndex.init(res)

func decodeString*(t: typedesc[Eth2Digest],
                   value: string): Result[Eth2Digest, cstring] =
  if len(value) != RootHashSize + 2:
    return err("Incorrect root value length")
  if value[0] != '0' and value[1] != 'x':
    return err("Incorrect root value encoding")
  parseRoot(value)

func decodeString*(t: typedesc[ValidatorFilter],
                   value: string): Result[ValidatorFilter, cstring] =
  ValidatorFilter.parse(value)
func decodeString*(t: typedesc[ConsensusFork],
                   value: string): Result[ConsensusFork, cstring] =
  ConsensusFork.init(toLowerAscii(value)) or
    err("Unsupported or invalid beacon block fork version")

proc decodeString*(t: typedesc[EventBeaconBlockObject],
                   value: string): Result[EventBeaconBlockObject, string] =
  try:
    ok(RestJson.decode(value, t))
  except SerializationError as exc:
    err(exc.formatMsg("<data>"))
