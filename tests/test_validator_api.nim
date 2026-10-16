# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}
{.used.}

import
  std/[sequtils, strutils],
  stew/byteutils,
  results, chronos, presto, unittest2,
  chronos/apps/http/httpclient,
  chronos/unittest2/asynctests,
  ../beacon_chain/spec/[crypto, eth2_ssz_serialization, forks],
  ../beacon_chain/spec/mev/gloas_mev,
  ../beacon_chain/rpc/[rest_utils, rest_validator_api],
  ../beacon_chain/beacon_node

proc testSuite() =
  suite "Builder preferences REST API test suite":
    const
      BuilderBadRequestMessage = "Auth slot has already passed"
      BuilderUnauthorizedMessage = "Invalid auth signature"
      BuilderInternalErrorMessage = "Builder is unavailable"

    type
      MockBehavior {.pure.} = enum
        Accept, BadRequest, Unauthorized, InternalError

      ReceivedSubmission = object
        proposerPubkey: ValidatorPubKey
        consensusVersion: string
        body: BuilderPreferencesRequest

      MockBuilderRef = ref object
        overrides: seq[(ValidatorPubKey, MockBehavior)]
        received: seq[ReceivedSubmission]

      RawResponse = object
        status: int
        contentType: string
        data: seq[byte]

    let
      pubkey1 = ValidatorPubKey.fromHex(
        "0x000000000000000000000000000000000000000000000000" &
        "000000000000000000000000000000000000000000000001").expect("pubkey")
      pubkey2 = ValidatorPubKey.fromHex(
        "0x000000000000000000000000000000000000000000000000" &
        "000000000000000000000000000000000000000000000002").expect("pubkey")
      pubkey3 = ValidatorPubKey.fromHex(
        "0x000000000000000000000000000000000000000000000000" &
        "000000000000000000000000000000000000000000000003").expect("pubkey")
      pubkey4 = ValidatorPubKey.fromHex(
        "0x000000000000000000000000000000000000000000000000" &
        "000000000000000000000000000000000000000000000004").expect("pubkey")
      # The builder is mocked and never verifies it, so any 96 bytes will do.
      mockSignature =
        ValidatorSig.fromHex("0x" & "ab".repeat(96)).expect("signature")

    proc makeEntry(
        proposerPubkey: ValidatorPubKey,
        url: string,
        maxExecutionPayment: Gwei,
        authData: openArray[byte]
    ): RestBuilderPreferencesEntry =
      RestBuilderPreferencesEntry(
        proposer_pubkey: proposerPubkey,
        url: BuilderUrlData.init(url.toBytes()),
        auth: SignedBuilderRequestAuth(
          message: BuilderRequestAuth(
            data: BuilderRequestAuthData.init(@authData),
            slot: Slot(1_000_000)),
          signature: mockSignature),
        max_execution_payment: maxExecutionPayment)

    proc encodeEntries(
        entries: openArray[RestBuilderPreferencesEntry], contentType: MediaType
    ): seq[byte] =
      if contentType == ApplicationJsonMediaType:
        try:
          RestJson.encode(@entries).toBytes()
        except SerializationError as exc:
          raiseAssert "Unable to encode JSON body: " & exc.msg
      elif contentType == OctetStreamMediaType:
        SSZ.encode(RestBuilderPreferencesEntryList.init(@entries))
      else:
        raiseAssert "Unsupported content type: " & $contentType

    proc behaviorFor(
        builder: MockBuilderRef, pubkey: ValidatorPubKey): MockBehavior =
      for (key, behavior) in builder.overrides:
        if key == pubkey:
          return behavior
      MockBehavior.Accept

    proc clear(builder: MockBuilderRef) =
      builder.overrides.setLen(0)
      builder.received.setLen(0)

    proc findSubmission(
        builder: MockBuilderRef, pubkey: ValidatorPubKey
    ): Opt[ReceivedSubmission] =
      for item in builder.received:
        if item.proposerPubkey == pubkey:
          return Opt.some(item)
      Opt.none(ReceivedSubmission)

    proc setupMockBuilderAPI(router: var RestRouter, builder: MockBuilderRef) =
      # https://github.com/ethereum/builder-specs/blob/5aef563dc3532a5009fef02bae97ca563ec28e5b/apis/builder/builder_preferences.yaml
      router.api2(MethodPost,
                  "/eth/v1/builder/builder_preferences/{proposer_pubkey}") do (
          proposer_pubkey: ValidatorPubKey,
          contentBody: Option[ContentBody]) -> RestApiResponse:
        let
          pubkey = proposer_pubkey.valueOr:
            return RestApiResponse.jsonError(
              Http400, "Invalid proposer_pubkey", $error)
          consensusVersion = request.headers.getString("eth-consensus-version")
        if contentBody.isNone():
          return RestApiResponse.jsonError(Http400, EmptyRequestBodyError)
        let body = decodeBodyJsonOrSsz(
            BuilderPreferencesRequest, contentBody.get()).valueOr:
          return RestApiResponse.jsonError(error)

        builder.received.add(ReceivedSubmission(
          proposerPubkey: pubkey, consensusVersion: consensusVersion,
          body: body))

        case builder.behaviorFor(pubkey)
        of MockBehavior.Accept:
          RestApiResponse.response(Http202)
        of MockBehavior.BadRequest:
          RestApiResponse.jsonError(Http400, BuilderBadRequestMessage)
        of MockBehavior.Unauthorized:
          RestApiResponse.jsonError(Http401, BuilderUnauthorizedMessage)
        of MockBehavior.InternalError:
          RestApiResponse.jsonError(Http500, BuilderInternalErrorMessage)

    proc startServer(router: RestRouter): (RestServerRef, string) =
      let
        bindAddress =
          try:
            initTAddress("127.0.0.1", Port(0))
          except TransportAddressError as exc:
            raiseAssert "Unexpected error, reason " & $exc.msg
        server = RestServerRef.new(router, bindAddress).valueOr:
          raiseAssert "Unable to establish REST server, reason " & $error
      server.start()
      (server, "http://" & $server.localAddress())

    proc postBuilderPreferences(
        session: HttpSessionRef,
        baseUri: string,
        body: seq[byte],
        contentType: MediaType,
        consensusFork = Opt.some(ConsensusFork.Gloas)
    ): Future[RawResponse] {.async: (raises: [CancelledError, HttpError]).} =
      var headers: seq[HttpHeaderTuple] = @[("Content-Type", $contentType)]
      if consensusFork.isSome():
        headers.add(("Eth-Consensus-Version", consensusFork.get().toString()))
      let request = HttpClientRequestRef.new(
          session, baseUri & "/eth/v1/validator/builder_preferences",
          MethodPost,
          headers = headers, body = body).valueOr:
        raiseAssert "Unable to create HTTP request: " & error
      try:
        let response = await request.send()
        try:
          let data = await response.getBodyBytes()
          RawResponse(
            status: response.status,
            contentType: response.headers.getString("content-type"),
            data: data)
        finally:
          await response.closeWait()
      finally:
        await request.closeWait()

    proc decodeIndexedError(response: RawResponse): RestIndexedErrorMessage =
      try:
        RestJson.decode(response.data, RestIndexedErrorMessage)
      except SerializationError as exc:
        raiseAssert "Unable to decode indexed error: " & exc.msg &
                    ", body: " & string.fromBytes(response.data)

    proc decodeError(response: RawResponse): RestErrorMessage =
      try:
        RestJson.decode(response.data, RestErrorMessage)
      except SerializationError as exc:
        raiseAssert "Unable to decode error: " & exc.msg &
                    ", body: " & string.fromBytes(response.data)

    let
      builderA = MockBuilderRef()
      builderB = MockBuilderRef()

    var
      builderRouterA = RestRouter.init(proc(p: string, v: string): int = 0)
      builderRouterB = RestRouter.init(proc(p: string, v: string): int = 0)
      nodeRouter = RestRouter.init(proc(p: string, v: string): int = 0)
    builderRouterA.setupMockBuilderAPI(builderA)
    builderRouterB.setupMockBuilderAPI(builderB)
    # The builder preferences handler never touches `node`, so an empty
    # `BeaconNode` is enough here and avoids starting a whole node.
    nodeRouter.installValidatorApiHandlers(BeaconNode())

    let
      (builderServerA, builderUrlA) = startServer(builderRouterA)
      (builderServerB, builderUrlB) = startServer(builderRouterB)
      (nodeServer, nodeUri) = startServer(nodeRouter)

    setup:
      builderA.clear()
      builderB.clear()
      let session = HttpSessionRef.new()

    teardown:
      waitFor session.closeWait()

    template forwardsAllEntriesTest(contentType: MediaType): untyped =
      let
        entries = @[
          makeEntry(pubkey1, builderUrlA, 1_000_000_000.Gwei, [byte 0x01]),
          # Multiple entries may share the same url; each one is submitted.
          makeEntry(
            pubkey2, builderUrlA, 2_000_000_000.Gwei, [byte 0x02, 0x03]),
          makeEntry(pubkey3, builderUrlB, 3_000_000_000.Gwei, [])]
        body = encodeEntries(entries, contentType)
        response = await session.postBuilderPreferences(
          nodeUri, body, contentType)

      check:
        response.status == 200
        builderA.received.len == 2
        builderB.received.len == 1

      for (builder, entry) in [(builderA, entries[0]), (builderA, entries[1]),
                               (builderB, entries[2])]:
        let submission = builder.findSubmission(entry.proposer_pubkey)
        check submission.isSome()
        if submission.isSome():
          let item = submission.get()
          check:
            item.consensusVersion == ConsensusFork.Gloas.toString()
            item.body.preferences.max_execution_payment ==
              entry.max_execution_payment
            # The auth must be forwarded byte-for-byte unchanged.
            SSZ.encode(item.body.auth) == SSZ.encode(entry.auth)

    asyncTest "Entries are forwarded to their builders [json]":
      forwardsAllEntriesTest(ApplicationJsonMediaType)

    asyncTest "Entries are forwarded to their builders [ssz]":
      forwardsAllEntriesTest(OctetStreamMediaType)

    asyncTest "Builder errors are proxied per entry index":
      let entries = @[
        makeEntry(pubkey1, builderUrlA, 1.Gwei, [byte 0x01]),
        makeEntry(pubkey2, builderUrlA, 2.Gwei, [byte 0x02]),
        makeEntry(pubkey3, builderUrlB, 3.Gwei, [byte 0x03]),
        makeEntry(pubkey4, builderUrlB, 4.Gwei, [byte 0x04])]
      builderA.overrides.add((pubkey2, MockBehavior.BadRequest))
      builderB.overrides.add((pubkey3, MockBehavior.Unauthorized))
      builderB.overrides.add((pubkey4, MockBehavior.InternalError))

      let
        contentType = ApplicationJsonMediaType
        body = encodeEntries(entries, contentType)
        response = await session.postBuilderPreferences(
          nodeUri, body, contentType)

      check:
        response.status == 400
        # A failing entry must not stop the other entries being submitted.
        builderA.findSubmission(pubkey1).isSome()
        builderA.findSubmission(pubkey2).isSome()
        builderB.findSubmission(pubkey3).isSome()
        builderB.findSubmission(pubkey4).isSome()

      # Any builder error, whatever its status code, is reported against its
      # entry with the builder's own message.
      let error = decodeIndexedError(response)
      check:
        error.code == 400
        error.message == BuilderPreferencesSubmissionError
        error.failures.len == 3
        error.failures.mapIt(it.index) == @[1, 2, 3]
      if error.failures.len == 3:
        check:
          error.failures[0].message == BuilderBadRequestMessage
          error.failures[1].message == BuilderUnauthorizedMessage
          error.failures[2].message == BuilderInternalErrorMessage

    asyncTest "Invalid builder url is reported per entry index":
      let
        entries = @[
          makeEntry(pubkey1, builderUrlA, 1.Gwei, [byte 0x01]),
          makeEntry(pubkey2, "not a url", 2.Gwei, [byte 0x02])]
        contentType = OctetStreamMediaType
        body = encodeEntries(entries, contentType)
        response = await session.postBuilderPreferences(
          nodeUri, body, contentType)

      check:
        response.status == 400
        builderA.received.len == 1

      let error = decodeIndexedError(response)
      check:
        error.failures.len == 1
        error.failures.mapIt(it.index) == @[1]

    asyncTest "Missing or pre-Gloas Eth-Consensus-Version is rejected":
      let
        entries = @[makeEntry(pubkey1, builderUrlA, 1.Gwei, [])]
        contentType = ApplicationJsonMediaType
        body = encodeEntries(entries, contentType)
        missing = await session.postBuilderPreferences(
          nodeUri, body, contentType, consensusFork = Opt.none(ConsensusFork))
        preGloas = await session.postBuilderPreferences(
          nodeUri, body, contentType,
          consensusFork = Opt.some(ConsensusFork.Fulu))

      check:
        missing.status == 400
        preGloas.status == 400
        decodeError(preGloas).message == UnsupportedForkError
        builderA.received.len == 0

    asyncTest "Empty and malformed request bodies are rejected":
      let
        empty = await session.postBuilderPreferences(
          nodeUri, @[], ApplicationJsonMediaType)
        badJson = await session.postBuilderPreferences(
          nodeUri, "[{\"proposer_pubkey\": 1}]".toBytes(),
          ApplicationJsonMediaType)
        badSsz = await session.postBuilderPreferences(
          nodeUri, @[byte 0x01, 0x02, 0x03], OctetStreamMediaType)

      check:
        empty.status == 400
        badJson.status == 400
        badSsz.status == 400
        builderA.received.len == 0

    asyncTest "Unsupported content type is rejected":
      let
        entries = @[makeEntry(pubkey1, builderUrlA, 1.Gwei, [])]
        body = encodeEntries(entries, ApplicationJsonMediaType)
        response = await session.postBuilderPreferences(
          nodeUri, body, MediaType.init("text/plain"))

      check:
        response.status == 415
        builderA.received.len == 0

    suiteTeardown:
      waitFor nodeServer.stop()
      waitFor builderServerA.stop()
      waitFor builderServerB.stop()
      waitFor nodeServer.closeWait()
      waitFor builderServerA.closeWait()
      waitFor builderServerB.closeWait()

testSuite()
