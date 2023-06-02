# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import std/strutils
import unittest2
import chronos/unittest2/asynctests
import ../beacon_chain/validator_client/common

const
  HostNames = [
    "[2001:db8::1]",
    "127.0.0.1",
    "hostname.com",
    "localhost",
    "username:password@[2001:db8::1]",
    "username:password@127.0.0.1",
    "username:password@hostname.com",
    "username:password@localhost",
  ]

  GoodTestVectors = [
    ("http://$1",
     "ok(http://$1)"),
    ("http://$1?q=query",
     "ok(http://$1?q=query)"),
    ("http://$1?q=query#anchor",
     "ok(http://$1?q=query#anchor)"),
    ("http://$1/subpath/",
     "ok(http://$1/subpath/)"),
    ("http://$1/subpath/q=query",
     "ok(http://$1/subpath/q=query)"),
    ("http://$1/subpath/q=query#anchor",
     "ok(http://$1/subpath/q=query#anchor)"),
    ("http://$1/subpath",
     "ok(http://$1/subpath)"),
    ("http://$1/subpath?q=query",
     "ok(http://$1/subpath?q=query)"),
    ("http://$1/subpath?q=query#anchor",
     "ok(http://$1/subpath?q=query#anchor)"),

    ("https://$1",
     "ok(https://$1)"),
    ("https://$1?q=query",
     "ok(https://$1?q=query)"),
    ("https://$1?q=query#anchor",
     "ok(https://$1?q=query#anchor)"),
    ("https://$1/subpath/",
     "ok(https://$1/subpath/)"),
    ("https://$1/subpath/q=query",
     "ok(https://$1/subpath/q=query)"),
    ("https://$1/subpath/q=query#anchor",
     "ok(https://$1/subpath/q=query#anchor)"),
    ("https://$1/subpath",
     "ok(https://$1/subpath)"),
    ("https://$1/subpath?q=query",
     "ok(https://$1/subpath?q=query)"),
    ("https://$1/subpath?q=query#anchor",
     "ok(https://$1/subpath?q=query#anchor)"),

    ("$1:5052",
     "ok(http://$1:5052)"),
    ("$1:5052?q=query",
     "ok(http://$1:5052?q=query)"),
    ("$1:5052?q=query#anchor",
     "ok(http://$1:5052?q=query#anchor)"),
    ("$1:5052/subpath/",
     "ok(http://$1:5052/subpath/)"),
    ("$1:5052/subpath/q=query",
     "ok(http://$1:5052/subpath/q=query)"),
    ("$1:5052/subpath/q=query#anchor",
     "ok(http://$1:5052/subpath/q=query#anchor)"),
    ("$1:5052/subpath",
     "ok(http://$1:5052/subpath)"),
    ("$1:5052/subpath?q=query",
     "ok(http://$1:5052/subpath?q=query)"),
    ("$1:5052/subpath?q=query#anchor",
     "ok(http://$1:5052/subpath?q=query#anchor)"),

    ("bnode://$1:5052",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052?q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052?q=query#anchor",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath/q=query#anchor",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath?q=query",
     "err(Unknown scheme value)"),
    ("bnode://$1:5052/subpath?q=query#anchor",
     "err(Unknown scheme value)"),

    ("//$1:5052",
     "ok(http://$1:5052)"),
    ("//$1:5052?q=query",
     "ok(http://$1:5052?q=query)"),
    ("//$1:5052?q=query#anchor",
     "ok(http://$1:5052?q=query#anchor)"),
    ("//$1:5052/subpath/",
     "ok(http://$1:5052/subpath/)"),
    ("//$1:5052/subpath/q=query",
     "ok(http://$1:5052/subpath/q=query)"),
    ("//$1:5052/subpath/q=query#anchor",
     "ok(http://$1:5052/subpath/q=query#anchor)"),
    ("//$1:5052/subpath",
     "ok(http://$1:5052/subpath)"),
    ("//$1:5052/subpath?q=query",
     "ok(http://$1:5052/subpath?q=query)"),
    ("//$1:5052/subpath?q=query#anchor",
     "ok(http://$1:5052/subpath?q=query#anchor)"),

    ("//$1", "err(Missing port number)"),
    ("//$1?q=query", "err(Missing port number)"),
    ("//$1?q=query#anchor", "err(Missing port number)"),
    ("//$1/subpath/", "err(Missing port number)"),
    ("//$1/subpath/q=query", "err(Missing port number)"),
    ("//$1/subpath/q=query#anchor", "err(Missing port number)"),
    ("//$1/subpath", "err(Missing port number)"),
    ("//$1/subpath?q=query", "err(Missing port number)"),
    ("//$1/subpath?q=query#anchor", "err(Missing port number)"),

    ("$1", "err(Missing port number)"),
    ("$1?q=query", "err(Missing port number)"),
    ("$1?q=query#anchor", "err(Missing port number)"),
    ("$1/subpath/", "err(Missing port number)"),
    ("$1/subpath/q=query", "err(Missing port number)"),
    ("$1/subpath/q=query#anchor", "err(Missing port number)"),
    ("$1/subpath", "err(Missing port number)"),
    ("$1/subpath?q=query", "err(Missing port number)"),
    ("$1/subpath?q=query#anchor", "err(Missing port number)"),

    ("", "err(Missing hostname)")
  ]

  ObolBeaconRequestTestVector = """
[
  {
    "validator_index": "1",
    "slot": "1",
    "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "slot": "2",
    "validator_index": "2",
    "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "validator_index": "3",
    "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
    "slot": "3"
  },
  {
    "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
    "validator_index": "4",
    "slot": "4"
  }
]"""
  ObolBeaconResponseTestVector = """
{
  "data": [
    {
      "validator_index": "1",
      "slot": "1",
      "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "2",
      "slot": "2",
      "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "3",
      "slot": "3",
      "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "4",
      "slot": "4",
      "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    }
  ]
}"""
  ObolBeaconResponseTestVectorObject = [
    (
      validator_index: RestValidatorIndex(1),
      slot: Slot(1),
      selection_proof: "1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(2),
      slot: Slot(2),
      selection_proof: "2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(3),
      slot: Slot(3),
      selection_proof: "3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(4),
      slot: Slot(4),
      selection_proof: "4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    )
  ]
  ObolSyncRequestTestVector = """
[
  {
    "validator_index": "1",
    "slot": "1",
    "subcommittee_index": "1",
    "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "validator_index": "2",
    "subcommittee_index": "2",
    "slot": "2",
    "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "subcommittee_index": "3",
    "validator_index": "3",
    "slot": "3",
    "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
  },
  {
    "validator_index": "4",
    "slot": "4",
    "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
    "subcommittee_index": "4"
  }
]"""
  ObolSyncResponseTestVector = """
{
  "data": [
    {
      "validator_index": "1",
      "slot": "1",
      "subcommittee_index": "1",
      "selection_proof": "0x1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "2",
      "subcommittee_index": "2",
      "slot": "2",
      "selection_proof": "0x2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "subcommittee_index": "3",
      "validator_index": "3",
      "slot": "3",
      "selection_proof": "0x3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    },
    {
      "validator_index": "4",
      "slot": "4",
      "selection_proof": "0x4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505",
      "subcommittee_index": "4"
    }
  ]
}"""
  ObolSyncResponseTestVectorObject = [
    (
      validator_index: RestValidatorIndex(1),
      slot: Slot(1),
      subcommittee_index: 1'u64,
      selection_proof: "1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(2),
      slot: Slot(2),
      subcommittee_index: 2'u64,
      selection_proof: "2b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(3),
      slot: Slot(3),
      subcommittee_index: 3'u64,
      selection_proof: "3b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    ),
    (
      validator_index: RestValidatorIndex(4),
      slot: Slot(4),
      subcommittee_index: 4'u64,
      selection_proof: "4b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505cc411d61252fb6cb3fa0017b679f8bb2305b26a285fa2737f175668d0dff91cc1b66ac1fb663c9bc59509846d6ec05345bd908eda73e670af888da41af171505"
    )
  ]

type
  TestDecodeTypes = seq[RestBeaconCommitteeSelection] |
                    seq[RestSyncCommitteeSelection]

suite "Validator Client test suite":
  proc decodeBytes[T: TestDecodeTypes](
         t: typedesc[T],
         value: openArray[byte],
         contentType: Opt[ContentTypeData] = Opt.none(ContentTypeData)
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
        err("Serialization error")
    else:
      err("Content-Type not supported")

  proc submitBeaconCommitteeSelectionsPlain(
         body: seq[RestBeaconCommitteeSelection]
       ): RestPlainResponse {.
       rest, endpoint: "/eth/v1/validator/beacon_committee_selections",
       meth: MethodPost.}
    ## https://ethereum.github.io/beacon-APIs/#/Validator/submitBeaconCommitteeSelections

  proc submitSyncCommitteeSelectionsPlain(
         body: seq[RestSyncCommitteeSelection]
       ): RestPlainResponse {.
       rest, endpoint: "/eth/v1/validator/sync_committee_selections",
       meth: MethodPost.}
    ## https://ethereum.github.io/beacon-APIs/#/Validator/submitSyncCommitteeSelections

  proc createServer(address: TransportAddress,
                    process: HttpProcessCallback, secure: bool): HttpServerRef =
    let
      socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      res =
        try:
          HttpServerRef.new(address, process, socketFlags = socketFlags)
        except CatchableError as exc:
          raiseAssert "Got an exception " & $exc.msg
    res.get()

  test "normalizeUri() test vectors":
    for hostname in HostNames:
      for vector in GoodTestVectors:
        let expect = vector[1] % (hostname)
        check $normalizeUri(parseUri(vector[0] % (hostname))) == expect

  asyncTest "/eth/v1/validator/sync_committee_selections " &
            "serialization/deserialization test":
    var clientRequest: seq[byte]
    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/eth/v1/validator/beacon_committee_selections":
          clientRequest = await request.getBody()
          let headers = HttpTable.init([("Content-Type", "application/json")])
          return await request.respond(Http200, ObolBeaconResponseTestVector,
                                       headers)
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return dumbResponse()

    let  server = createServer(initTAddress("127.0.0.1:0"), process, false)
    server.start()
    defer:
      await server.stop()
      await server.closeWait()

    let
      serverAddress = server.instance.localAddress
      flags = {RestClientFlag.CommaSeparatedArray}
      remoteUri = "http://" & $serverAddress
      client =
        block:
          let res = RestClientRef.new(remoteUri, flags = flags)
          check res.isOk()
          res.get()
      selections =
        block:
          let res = decodeBytes(
            seq[RestBeaconCommitteeSelection],
            ObolBeaconRequestTestVector.toOpenArrayByte(
              0, len(ObolBeaconRequestTestVector) - 1))
          check res.isOk()
          res.get()

    defer:
      await client.closeWait()

    let resp = await client.submitBeaconCommitteeSelectionsPlain(selections)
    check:
      resp.status == 200
      resp.contentType == MediaType.init("application/json")

    let request =
      block:
        let res = decodeBytes(
          seq[RestBeaconCommitteeSelection],
          clientRequest)
        check res.isOk()
        res.get()

    let response = block:
      let res = decodeBytes(SubmitBeaconCommitteeSelectionsResponse,
                            resp.data, resp.contentType)
      check res.isOk()
      res.get()

    check:
      len(request) == len(selections)
      len(response.data) == len(ObolBeaconResponseTestVectorObject)

    # Checking response
    for index, item in response.data.pairs():
      check:
        item.validator_index ==
          ObolBeaconResponseTestVectorObject[index].validator_index
        item.slot ==
          ObolBeaconResponseTestVectorObject[index].slot
        item.selection_proof.toHex() ==
          ObolBeaconResponseTestVectorObject[index].selection_proof

    # Checking request
    for index, item in selections.pairs():
      check:
        item.validator_index == request[index].validator_index
        item.slot == request[index].slot
        item.selection_proof.toHex() == request[index].selection_proof.toHex()



  asyncTest "/eth/v1/validator/sync_committee_selections " &
            "serialization/deserialization test":

    var clientRequest: seq[byte]
    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/eth/v1/validator/sync_committee_selections":
          clientRequest = await request.getBody()
          let headers = HttpTable.init([("Content-Type", "application/json")])
          return await request.respond(Http200, ObolSyncResponseTestVector,
                                       headers)
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return dumbResponse()

    let  server = createServer(initTAddress("127.0.0.1:0"), process, false)
    server.start()
    defer:
      await server.stop()
      await server.closeWait()

    let
      serverAddress = server.instance.localAddress
      flags = {RestClientFlag.CommaSeparatedArray}
      remoteUri = "http://" & $serverAddress
      client =
        block:
          let res = RestClientRef.new(remoteUri, flags = flags)
          check res.isOk()
          res.get()
      selections =
        block:
          let res = decodeBytes(
            seq[RestSyncCommitteeSelection],
            ObolSyncRequestTestVector.toOpenArrayByte(
              0, len(ObolSyncRequestTestVector) - 1))
          check res.isOk()
          res.get()

    defer:
      await client.closeWait()

    let resp = await client.submitSyncCommitteeSelectionsPlain(selections)
    check:
      resp.status == 200
      resp.contentType == MediaType.init("application/json")

    let request =
      block:
        let res = decodeBytes(
          seq[RestSyncCommitteeSelection],
          clientRequest)
        check res.isOk()
        res.get()

    let response = block:
      let res = decodeBytes(SubmitSyncCommitteeSelectionsResponse,
                            resp.data, resp.contentType)
      check res.isOk()
      res.get()

    check:
      len(request) == len(selections)
      len(response.data) == len(ObolSyncResponseTestVectorObject)

    # Checking response
    for index, item in response.data.pairs():
      check:
        item.validator_index ==
          ObolSyncResponseTestVectorObject[index].validator_index
        item.slot ==
          ObolSyncResponseTestVectorObject[index].slot
        item.selection_proof.toHex() ==
          ObolSyncResponseTestVectorObject[index].selection_proof
        item.subcommittee_index == request[index].subcommittee_index

    # Checking request
    for index, item in selections.pairs():
      check:
        item.validator_index == request[index].validator_index
        item.slot == request[index].slot
        item.subcommittee_index == request[index].subcommittee_index
        item.selection_proof.toHex() == request[index].selection_proof.toHex()
