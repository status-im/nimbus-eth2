# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  stew/[bitseqs, endians2, objects],
  blscurve, bearssl/rand,
  results, chronos, presto, unittest2,
  chronos/unittest2/asynctests,
  ../beacon_chain/spec/[presets, crypto, signatures, eth2_ssz_serialization,
                        helpers, forks],
  ../beacon_chain/spec/mev/[electra_mev, fulu_mev, rest_mev_calls],
  ../beacon_chain/rpc/rest_utils

from std/times import Time, toUnix, fromUnix, getTime

const
  ElectraSlot = Slot(64000)
  FuluSlot = Slot(96000)
  emptyFork = Fork()
  emptyRoot = Eth2Digest()

type
  MevBlocks = electra_mev.SignedBlindedBeaconBlock |
              fulu_mev.SignedBlindedBeaconBlock

  TestNodeRef* = ref object
    validators: seq[ValidatorPubKey]

  TestKind* {.pure.} = enum
    Json, Ssz

proc keyGen(rng: var HmacDrbgContext): BlsResult[ValidatorPrivKey] =
  var
    pubkey: blscurve.PublicKey
    seckey: blscurve.SecretKey
  let bytes = rng.generate(array[32, byte])
  if not keyGen(bytes, pubkey, seckey):
    return err "key generation failed"
  ok(ValidatorPrivKey(seckey))

func specifiedFeeRecipient(x: int): Eth1Address =
  copyMem(addr result, unsafeAddr x, sizeof x)

proc prepareRegistration(
    fork: Fork,
    key: ValidatorPrivKey,
    gas_limit: uint64 = 0'u64,
    timestamp: Time,
    feeRecipient: Eth1Address
): SignedValidatorRegistrationV1 =
  var msg =
    SignedValidatorRegistrationV1(
      message: ValidatorRegistrationV1(
        fee_recipient: ExecutionAddress(data: distinctBase(feeRecipient)),
        gas_limit: gas_limit,
        timestamp: uint64(timestamp.toUnix()),
        pubkey: key.toPubKey().toPubKey()
      ))
  msg.signature = get_builder_signature(fork, msg.message, key).toValidatorSig()
  msg

proc generateRegistrations(
    rng: var HmacDrbgContext,
    count: int
): seq[SignedValidatorRegistrationV1] =
  var res: seq[SignedValidatorRegistrationV1]
  for index in 0 ..< count:
    let
      privateKey = keyGen(rng).valueOr:
        raiseAssert "Unable to generate private key"
      feeRecipient = specifiedFeeRecipient(index)
    res.add(prepareRegistration(
      emptyFork, privateKey, 30_000_000'u64, getTime(), feeRecipient))
  res

proc prepare(
    T: typedesc[MevBlocks],
    slot: Slot,
    parent_hash: Eth2Digest,
    proposer_index: uint64,
    privateKey: ValidatorPrivKey
): T =
  var tmp: T
  let
    blindedBlock = typeof(tmp.message)(
      slot: slot,
      proposer_index: proposer_index,
      body: typeof(tmp.message.body)(
        execution_payload_header:
          typeof(tmp.message.body.execution_payload_header)(
            parent_hash: parent_hash
    )))
    block_root = hash_tree_root(blindedBlock)
  T(message: blindedBlock,
    signature: get_block_signature(emptyFork, emptyRoot, slot, block_root,
                                   privateKey).toValidatorSig())

proc jsonResponseSignedBuilderBid(
    t: typedesc[RestApiResponse],
    bid: electra_mev.SignedBuilderBid | fulu_mev.SignedBuilderBid
): RestApiResponse =
  let
    consensusFork = typeof(bid).kind()
    headers = [("eth-consensus-version", consensusFork.toString())]
    res =
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("version", consensusFork.toString())
        writer.writeField("data", bid)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except IOError:
        default(seq[byte])
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc jsonResponseExecutionPayloadAndBlobsBundle(
    t: typedesc[RestApiResponse],
    payload: electra_mev.ExecutionPayloadAndBlobsBundle
): RestApiResponse =
  let
    consensusFork = typeof(payload).kind()
    headers = [("eth-consensus-version", consensusFork.toString())]
    res =
      try:
        var stream = memoryOutput()
        var writer = JsonWriter[RestJson].init(stream)
        writer.beginRecord()
        writer.writeField("version", consensusFork.toString())
        writer.writeField("data", payload)
        writer.endRecord()
        stream.getOutput(seq[byte])
      except IOError:
        default(seq[byte])
  RestApiResponse.response(res, Http200, "application/json", headers = headers)

proc sszResponseSignedBuilderBid*(
    t: typedesc[RestApiResponse],
    bid: electra_mev.SignedBuilderBid | fulu_mev.SignedBuilderBid,
): RestApiResponse =
  mixin kind
  let
    consensusFork = typeof(bid).kind()
    headers = [("eth-consensus-version", consensusFork.toString())]
    res =
      try:
        var stream = memoryOutput()
        var writer = SszWriter.init(stream)
        writer.writeValue(bid)
        stream.getOutput(seq[byte])
      except IOError:
        default(seq[byte])
  RestApiResponse.response(res, Http200, "application/octet-stream",
                           headers = headers)

proc sszResponseExecutionPayloadAndBlobsBundle*(
    t: typedesc[RestApiResponse],
    payload: electra_mev.ExecutionPayloadAndBlobsBundle
): RestApiResponse =
  mixin kind
  let
    consensusFork = typeof(payload).kind()
    headers = [("eth-consensus-version", consensusFork.toString())]
    res =
      try:
        var stream = memoryOutput()
        var writer = SszWriter.init(stream)
        writer.writeValue(payload)
        stream.getOutput(seq[byte])
      except IOError:
        default(seq[byte])
  RestApiResponse.response(res, Http200, "application/octet-stream",
                           headers = headers)

proc setupEngineAPI*(router: var RestRouter, node: TestNodeRef) =
  router.api2(MethodPost, "/eth/v1/builder/validators") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:

    if contentBody.isNone:
      return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)

    let registrations =
      decodeBodyJsonOrSsz(seq[SignedValidatorRegistrationV1],
                          contentBody.get()).valueOr:
      return RestApiResponse.jsonError(error)

    for item in registrations:
      if not(verify_builder_signature(emptyFork, item.message,
                                      item.message.pubkey, item.signature)):
        return RestApiResponse.jsonError(Http400,
                                         "Signature verification failed")
    RestApiResponse.jsonResponse(Http200)

  router.api2(MethodGet,
              "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}") do (
    slot: Slot, parent_hash: Eth2Digest,
    pubkey: ValidatorPubKey) -> RestApiResponse:
    let
      qslot = slot.valueOr:
        return RestApiResponse.jsonError(Http400, "Invalid slot", $error)
      qhash = parent_hash.valueOr:
        return RestApiResponse.jsonError(Http400, "Invalid parent_hash", $error)
      qpubkey {.used.} = pubkey.valueOr:
        return RestApiResponse.jsonError(Http400, "Invalid pubkey", $error)
      contentType = preferredContentType(jsonMediaType,
                                         sszMediaType).valueOr:
        return RestApiResponse.jsonError(Http406, "Content is not acceptable")

    template respondSszOrJson(contentType, bid: auto): RestApiResponse =
      if contentType == sszMediaType:
        RestApiResponse.sszResponseSignedBuilderBid(bid)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseSignedBuilderBid(bid)
      else:
        RestApiResponse.jsonError(Http415, "Invalid Accept")

    if qslot == ElectraSlot:
      let bid = electra_mev.SignedBuilderBid(
        message: electra_mev.BuilderBid(
          header: electra.ExecutionPayloadHeader(parent_hash: qhash))
      )
      respondSszOrJson(contentType, bid)
    elif qslot == FuluSlot:
      let bid = fulu_mev.SignedBuilderBid(
        message: fulu_mev.BuilderBid(
          header: fulu.ExecutionPayloadHeader(parent_hash: qhash))
      )
      respondSszOrJson(contentType, bid)
    else:
      RestApiResponse.jsonError(Http500, "Unsupported slot number")

  router.api2(MethodPost, "/eth/v1/builder/blinded_blocks") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:

    if contentBody.isNone:
      return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)

    let
      rawVersion = request.headers.getString("eth-consensus-version")
      consensusFork = ConsensusFork.decodeString(rawVersion).valueOr:
        return RestApiResponse.jsonError(Http400, "Invalid consensus version")
      contentType = preferredContentType(jsonMediaType,
                                         sszMediaType).valueOr:
        return RestApiResponse.jsonError(Http406, "Content type not acceptable")

    if consensusFork < ConsensusFork.Electra:
      return RestApiResponse.jsonError(Http400, "Unsupported fork version")

    template respondSszOrJson(contentType, payload: auto): RestApiResponse =
      if contentType == sszMediaType:
        RestApiResponse.sszResponseExecutionPayloadAndBlobsBundle(payload)
      elif contentType == jsonMediaType:
        RestApiResponse.jsonResponseExecutionPayloadAndBlobsBundle(payload)
      else:
        RestApiResponse.jsonError(Http415, "Invalid Accept")

    if consensusFork == ConsensusFork.Electra:
      let
        blck =
          decodeBodyJsonOrSsz(electra_mev.SignedBlindedBeaconBlock,
                              contentBody.get()).valueOr:
            return RestApiResponse.jsonError(error)
        payload = electra_mev.ExecutionPayloadAndBlobsBundle(
          execution_payload: electra.ExecutionPayload(
            parent_hash: blck.message.body.execution_payload_header.parent_hash
          ),
          blobs_bundle: BlobsBundle()
        )
      respondSszOrJson(contentType, payload)
    else:
      raiseAssert "Unsupported fork version"

  router.api2(MethodPost, "/eth/v2/builder/blinded_blocks") do (
    contentBody: Option[ContentBody]) -> RestApiResponse:

    if contentBody.isNone:
      return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)

    let
      rawVersion = request.headers.getString("eth-consensus-version")
      consensusFork = ConsensusFork.decodeString(rawVersion).valueOr:
        return RestApiResponse.jsonError(Http400, "Invalid consensus version")
      contentType = preferredContentType(jsonMediaType,
                                         sszMediaType).valueOr:
        return RestApiResponse.jsonError(Http406, "Content type not acceptable")

    if consensusFork < ConsensusFork.Fulu:
      return RestApiResponse.jsonError(Http400, "Unsupported fork version")

    if contentType in [sszMediaType, jsonMediaType]:
      RestApiResponse.response(
        Http202, headers=[("eth-consensus-version", consensusFork.toString)])
    else:
      RestApiResponse.jsonError(Http415, "Invalid Accept")

  router.api2(MethodGet, "/eth/v1/builder/status") do () -> RestApiResponse:
    RestApiResponse.response(Http200)

proc testSuite() =
  suite "MEV calls serialization/deserialization and behavior test suite":
    let
      rng = HmacDrbgContext.new()
      node = TestNodeRef()
    var router = RestRouter.init(proc(pattern: string, value: string): int = 0)
    setupEngineAPI(router, node)

    let
      bindAddress = try:
        initTAddress("127.0.0.1", Port(0))
      except TransportAddressError as exc:
        raiseAssert "Unexpected error, reason " & $exc.msg

      server = RestServerRef.new(router, bindAddress).valueOr:
        raiseAssert "Unable to establish REST server, reason " & $error
      address = server.localAddress()

    server.start()

    setup:
      let
        httpFlags: set[HttpClientFlag] = {}
        prestoFlags = {RestClientFlag.CommaSeparatedArray}
        socketFlags = {SocketFlags.TcpNoDelay}
        remoteUri = "http://" & $address & "/"
        client = RestClientRef.new(
          remoteUri, prestoFlags, httpFlags, socketFlags = socketFlags).valueOr:
            raiseAssert "Unable to resolve distributed signer address " & $address

    teardown:
      waitFor client.closeWait()

    template getHeaderTest(responseKind: TestKind): untyped =
      let
        bytes = rng[].generate(array[32, byte])
        parent_hash = Eth2Digest(data: bytes)
        privateKey = keyGen(rng[]).valueOr:
          raiseAssert "Unable to generate private key"
        publicKey = privateKey.toPubKey().toPubKey()
        (restAcceptType1, responseMediaType1) =
          if responseKind == TestKind.Ssz:
            ("application/octet-stream", OctetStreamMediaType)
          else:
            ("application/json", ApplicationJsonMediaType)
        (restAcceptType2, responseMediaType2) =
          if responseKind == TestKind.Ssz:
            ("application/json;q=0.9,application/octet-stream",
             OctetStreamMediaType)
          else:
            ("application/octet-stream;q=0.9,application/json",
             ApplicationJsonMediaType)
        (restAcceptType3, responseMediaType3) =
          if responseKind == TestKind.Ssz:
            ("application/json;q=0.5,application/octet-stream;q=1.0",
             OctetStreamMediaType)
          else:
            ("application/octet-stream;q=0.5,application/json;q=1.0",
             ApplicationJsonMediaType)

      let
        response1 =
          await client.getHeaderPlain(ElectraSlot, parent_hash,
            publicKey, restAcceptType = restAcceptType1)
        response2 =
          await client.getHeaderPlain(ElectraSlot, parent_hash,
            publicKey, restAcceptType = restAcceptType2)
        response3 =
          await client.getHeaderPlain(FuluSlot, parent_hash,
            publicKey, restAcceptType = restAcceptType3)

      check:
        response1.status == 200
        response2.status == 200
        response3.status == 200
        response1.contentType.isSome()
        response2.contentType.isSome()
        response3.contentType.isSome()
        response1.contentType.get().mediaType == responseMediaType1
        response2.contentType.get().mediaType == responseMediaType2
        response3.contentType.get().mediaType == responseMediaType3

      let
        version1 = response1.headers.getString("eth-consensus-version")
        version2 = response2.headers.getString("eth-consensus-version")
        version3 = response3.headers.getString("eth-consensus-version")

      check:
        version1 == ConsensusFork.Electra.toString()
        version2 == ConsensusFork.Electra.toString()
        version3 == ConsensusFork.Fulu.toString()

      let
        bid1res =
          decodeBytesJsonOrSsz(GetHeaderResponseElectra, response1.data,
            response1.contentType, version1)
        bid2res =
          decodeBytesJsonOrSsz(GetHeaderResponseElectra, response2.data,
            response2.contentType, version2)
        bid3res =
          decodeBytesJsonOrSsz(GetHeaderResponseFulu, response3.data,
            response3.contentType, version3)

      check:
        bid1res.isOk()
        bid2res.isOk()
        bid3res.isOk()
        bid1res.get().data.message.header.parent_hash == parent_hash
        bid2res.get().data.message.header.parent_hash == parent_hash
        bid3res.get().data.message.header.parent_hash == parent_hash

    template submitBlindedBlockTest(
        requestKind: TestKind,
        responseKind: TestKind
    ): untyped =
      let
        parent_hash1 = Eth2Digest(data: rng[].generate(array[32, byte]))
        parent_hash2 = Eth2Digest(data: rng[].generate(array[32, byte]))
        parent_hash3 = Eth2Digest(data: rng[].generate(array[32, byte]))
        privateKey1 = keyGen(rng[]).valueOr:
          raiseAssert "Unable to generate private key"
        privateKey2 = keyGen(rng[]).valueOr:
          raiseAssert "Unable to generate private key"
        privateKey3 = keyGen(rng[]).valueOr:
          raiseAssert "Unable to generate private key"
        publicKey1 = privateKey1.toPubKey().toPubKey()
        publicKey2 = privateKey1.toPubKey().toPubKey()
        publicKey3 = privateKey1.toPubKey().toPubKey()

      node.validators.reset()
      node.validators.add(publicKey1)
      node.validators.add(publicKey2)
      node.validators.add(publicKey3)

      let
        blck1 =
          prepare(electra_mev.SignedBlindedBeaconBlock, ElectraSlot, parent_hash1,
                  0'u64, privateKey1)
        blck2 =
          prepare(electra_mev.SignedBlindedBeaconBlock, ElectraSlot, parent_hash2,
                  1'u64, privateKey2)
        blck3 =
          prepare(fulu_mev.SignedBlindedBeaconBlock, FuluSlot, parent_hash3,
                  2'u64, privateKey3)

        restContentType1 =
          if requestKind == TestKind.Ssz:
            "application/octet-stream"
          else:
            "application/json"
        restContentType2 =
          if requestKind == TestKind.Ssz:
            "application/octet-stream"
          else:
            "application/json"
        restContentType3 =
          if requestKind == TestKind.Ssz:
            "application/octet-stream"
          else:
            "application/json"
        (restAcceptType1, responseMediaType1) =
          if responseKind == TestKind.Ssz:
            ("application/octet-stream", OctetStreamMediaType)
          else:
            ("application/json", ApplicationJsonMediaType)
        (restAcceptType2, responseMediaType2) =
          if responseKind == TestKind.Ssz:
            ("application/octet-stream,application/json;q=0.9",
             OctetStreamMediaType)
          else:
            ("application/json,application/octet-stream;q=0.9",
             ApplicationJsonMediaType)
        (restAcceptType3, _) =
          if responseKind == TestKind.Ssz:
            ("application/json;q=0.5,application/octet-stream;q=1.0",
             OctetStreamMediaType)
          else:
            ("application/octet-stream;q=0.5,application/json;q=1.0",
             ApplicationJsonMediaType)

        response1 =
          await client.submitBlindedBlockPlain(
            blck1,
            restContentType = restContentType1,
            restAcceptType = restAcceptType1,
            extraHeaders = @[("eth-consensus-version",
                              toString(ConsensusFork.Electra))])
        response2 =
          await client.submitBlindedBlockPlain(
            blck2,
            restContentType = restContentType2,
            restAcceptType = restAcceptType2,
            extraHeaders = @[("eth-consensus-version",
                              toString(ConsensusFork.Electra))])
        response3 =
          await client.submitBlindedBlockV2Plain(
            blck3,
            restContentType = restContentType3,
            restAcceptType = restAcceptType3,
            extraHeaders = @[("eth-consensus-version",
                              toString(ConsensusFork.Fulu))])
      check:
        response1.status == 200
        response2.status == 200
        response3.status == 202

      let
        version1 = response1.headers.getString("eth-consensus-version")
        version2 = response2.headers.getString("eth-consensus-version")
        version3 = response3.headers.getString("eth-consensus-version")

      check:
        response1.contentType.isSome()
        response2.contentType.isSome()
        response1.contentType.get().mediaType == responseMediaType1
        response2.contentType.get().mediaType == responseMediaType2
        version1 == ConsensusFork.Electra.toString()
        version2 == ConsensusFork.Electra.toString()
        version3 == ConsensusFork.Fulu.toString()

      let
        payload1res =
          decodeBytesJsonOrSsz(SubmitBlindedBlockResponseElectra,
            response1.data, response1.contentType, version1)
        payload2res =
          decodeBytesJsonOrSsz(SubmitBlindedBlockResponseElectra,
            response2.data, response2.contentType, version2)

      check:
        payload1res.isOk()
        payload2res.isOk()
        payload1res.get().data.execution_payload.parent_hash == parent_hash1
        payload2res.get().data.execution_payload.parent_hash == parent_hash2

    asyncTest "/eth/v1/builder/status test":
      let response = await client.getStatus()
      check response.status == 200

    asyncTest "/eth/v1/builder/validators [json] test":
      let
        response1 =
          await client.registerValidator(
            generateRegistrations(rng[], 5))
        response2 =
          await client.registerValidator(
            generateRegistrations(rng[], 5),
            restContentType = "application/json")
      check:
        response1.status == 200
        response2.status == 200

    asyncTest "/eth/v1/builder/validators [ssz] test":
      let
        response =
          await client.registerValidator(
            generateRegistrations(rng[], 5),
            restContentType = "application/octet-stream")
      check response.status == 200

    asyncTest "/eth/v1/builder/header [json] test":
      getHeaderTest(TestKind.Json)

    asyncTest "/eth/v1/builder/header [ssz] test":
      getHeaderTest(TestKind.Ssz)

    asyncTest "/eth/v1/builder/blinded_blocks [json/json] test":
      submitBlindedBlockTest(TestKind.Json, TestKind.Json)

    asyncTest "/eth/v1/builder/blinded_blocks [json/ssz] test":
      submitBlindedBlockTest(TestKind.Json, TestKind.Ssz)

    asyncTest "/eth/v1/builder/blinded_blocks [ssz/ssz] test":
      submitBlindedBlockTest(TestKind.Ssz, TestKind.Ssz)

    asyncTest "/eth/v1/builder/blinded_blocks [ssz/json] test":
      submitBlindedBlockTest(TestKind.Ssz, TestKind.Json)

    suiteTeardown:
      waitFor server.stop()

testSuite()
