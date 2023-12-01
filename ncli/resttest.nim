# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/[strutils, os, options, uri, json, tables]
import stew/[results, io2, base10]
import confutils, chronicles, httputils,
       chronos, chronos/streams/[asyncstream, tlsstream]

const
  RestTesterName* = "Ethereum2 REST API Tester"
  RestTesterMajor*: int = 0
  RestTesterMinor*: int = 0
  RestTesterPatch*: int = 1
  RestTesterVersion* = $RestTesterMajor & "." & $RestTesterMinor & "." &
                       $RestTesterPatch
  RestTesterIdent* = "RestTester/$1 ($2/$3)" % [RestTesterVersion,
                                                hostCPU, hostOS]
  RestTesterCopyright* = "Copyright(C) 2021-2022" &
                        " Status Research & Development GmbH"
  RestTesterHeader* = RestTesterName & ", Version " & RestTesterVersion &
                      " [" & hostOS & ": " & hostCPU & "]\r\n" &
                      RestTesterCopyright & "\r\n"
  HeadersMark = @[0x0D'u8, 0x0A'u8, 0x0D'u8, 0x0A'u8]

type
  StatusOperatorKind* {.pure.} = enum
    Equals, OneOf, Inside, InsideOrEq

  HeaderOperatorKind {.pure.} = enum
    Exists, NotExists, Equals, OneOf, Substr

  BodyOperatorKind {.pure.} = enum
    Exists, JsonStructCmpS, JsonStructCmpNS,
    JsonStructCmpSAV, JsonStructCmpNSAV

  StatusExpect = object
    kind: StatusOperatorKind
    value: seq[int]

  HeaderExpect = object
    kind: HeaderOperatorKind
    key: string
    value: seq[string]

  HeadersExpect = object
    headers: seq[HeaderExpect]

  BodyItemExpect = object
    kind: BodyOperatorKind
    startPath: seq[string]
    value: JsonNode

  BodyExpect = object
    items: seq[BodyItemExpect]

  TestResultKind* {.pure.} = enum
    RuleError,
    NoSupportError,
    WriteRequestError,
    ReadResponseHeadersError,
    ReadResponseBodyError,
    RequestError,
    ResponseError,
    ValidationError,
    ValidationSuccess

  TestResultFlag* {.pure.} = enum
    ResetConnection, StatusValidationFailure,
    HeadersValidationFailure, BodyValidationFailure

  TestResult* = object
    kind: TestResultKind
    message: string
    flags: set[TestResultFlag]
    times: array[4, Duration]

  TestCase* = object
    index: int
    rule: JsonNode

  TestCaseResult* = object
    index: int
    data: TestResult

  HttpConnectionType* {.pure.} = enum
    Nonsecure, Secure

  HttpConnectionRef* = ref object
    case kind*: HttpConnectionType
    of HttpConnectionType.Nonsecure:
      discard
    of HttpConnectionType.Secure:
      stream: TLSAsyncStream
      treader: AsyncStreamReader
      twriter: AsyncStreamWriter
    transp: StreamTransport
    reader*: AsyncStreamReader
    writer*: AsyncStreamWriter

  RestTestError* = object of CatchableError
  ConnectionError* = object of RestTestError

  RestTesterConf* = object
    delayTime* {.
      defaultValue: 0
      desc: "Time (in seconds) to wait before initial connection could be " &
            "established"
      abbr: "d"
      name: "delay" .}: int

    attemptTimeout* {.
      defaultValue: 60
      desc: "Time (in seconds) during which to continue trying to establish " &
            "connection with remote server"
      name: "timeout" .}: int

    noVerifyCert* {.
      defaultValue: false
      desc: "Skip remote server SSL/TLS certificate validation"
      name: "no-verify-host" .}: bool

    noVerifyName* {.
      defaultValue: false
      desc: "Skep remote server name verification"
      name: "no-verify-name" .}: bool

    rulesFilename* {.
      defaultValue: "resttest-rules.json",
      desc: "JSON formatted tests file"
      name: "rules-file" .}: string

    topicsFilter* {.
      desc: "Topics which should be included in testing"
      name: "topic",
      abbr: "t" .}: seq[string]

    skipTopicsFilter* {.
      desc: "Topics which should be skipped in testing"
      name: "skip-topic",
      abbr: "s" .}: seq[string]

    connectionsCount* {.
      defaultValue: 1
      desc: "Number of concurrent connections to remote server"
      name: "connections"
      abbr: "c" .}: int

    url* {.
      argument,
      desc: "Address of remote REST server to test"
    .}: string

proc getUri(conf: RestTesterConf): Result[Uri, cstring] =
  var res = parseUri(conf.url)
  if res.scheme notin ["http", "https"]:
    return err("URL scheme should be http or https")
  if len(res.hostname) == 0:
    return err("URL missing hostname")
  if len(res.query) != 0:
    return err("URL should not contain query parameters")
  if len(res.anchor) != 0:
    return err("URL should not contain anchor parameter")
  # TODO: Disable this check when at least BASIC AUTH will be implemented.
  if len(res.username) != 0 or len(res.password) != 0:
    return err("URL should not contain username:password")
  if len(res.port) == 0:
    if res.scheme == "http":
      res.port = "80"
    else:
      res.port = "443"
  ok(res)

proc getAddress(uri: Uri): Result[TransportAddress, cstring] =
  let txtaddr = uri.hostname & ":" & uri.port
  let numeric =
    try:
      initTAddress(txtaddr)
    except TransportAddressError:
      # We ignore errors here because `hostname` address could be non-numeric.
      TransportAddress()
  if numeric.family in {AddressFamily.IPv4, AddressFamily.IPv6}:
    ok(numeric)
  else:
    var default: seq[TransportAddress]
    let v4addresses =
      try:
        resolveTAddress(txtaddr, AddressFamily.IPv4)
      except TransportAddressError:
        # We ignore errors here because `hostname` could be resolved to IPv6.
        default
    if len(v4addresses) > 0:
      ok(v4addresses[0])
    else:
      let v6addresses =
        try:
          resolveTAddress(txtaddr, AddressFamily.IPv6)
        except TransportAddressError:
          return err("Unable to resolve hostname")
      if len(v6addresses) == 0:
        return err("Unable to resolve hostname")
      ok(v6addresses[0])

proc getTLSFlags(conf: RestTesterConf): set[TLSFlags] =
  var res: set[TLSFlags]
  if conf.noVerifyName:
    res.incl(TLSFlags.NoVerifyServerName)
  if conf.noVerifyCert:
    res.incl(TLSFlags.NoVerifyHost)
  res

proc checkTopic(conf: RestTesterConf, rule: JsonNode): bool =
  var default: seq[string]
  if (len(conf.topicsFilter) == 0) and (len(conf.skipTopicsFilter) == 0):
    true
  else:
    let topics =
      block:
        let jtopics = rule.getOrDefault("topics")
        if isNil(jtopics):
          default
        else:
          case jtopics.kind
          of JString:
            @[jtopics.str]
          of JArray:
            if len(jtopics.elems) == 0:
              default
            else:
              var res: seq[string]
              for jitem in jtopics.elems:
                case jitem.kind:
                of JString:
                  res.add(jitem.str)
                else:
                  continue
              res
          else:
            default
    if len(conf.topicsFilter) == 0:
      if len(topics) == 0:
        true
      else:
        for item in topics:
          if item in conf.skipTopicsFilter:
            return false
        true
    else:
      for item in topics:
        if item in conf.skipTopicsFilter:
          return false
      for item in topics:
        if item in conf.topicsFilter:
          return true
      false

proc getTestRules(conf: RestTesterConf): Result[seq[JsonNode], cstring] =
  let data =
    block:
      let res = io2.readAllChars(conf.rulesFilename)
      if res.isErr():
        fatal "Could not read rules file", error_msg = ioErrorMsg(res.error()),
              error_os_code = $res.error(), filename = conf.rulesFilename
        return err("Unable to read rules file")
      res.get()
  let node =
    try:
      parseJson(data)
    except CatchableError as exc:
      fatal "JSON processing error while reading rules file",
            error_msg = exc.msg, filename = conf.rulesFilename
      return err("Unable to parse json")
    except Exception as exc:
      raiseAssert exc.msg

  let elems = node.getElems()
  if len(elems) == 0:
    fatal "There empty array of rules found in file",
          filename = conf.rulesFilename
    return err("Incorrect json")

  var res: seq[JsonNode]
  for item in elems:
    if conf.checkTopic(item):
      res.add(item)

  notice "Rules file loaded", total_rules_count = len(elems),
                              rules_count = len(res)
  ok(res)

proc openConnection*(address: TransportAddress, uri: Uri,
                    flags: set[TLSFlags]): Future[HttpConnectionRef] {.async.} =
  let transp =
    try:
      await connect(address)
    except TransportOsError:
      raise newException(ConnectionError, "Unable to establish connection")

  let treader = newAsyncStreamReader(transp)
  let twriter = newAsyncStreamWriter(transp)
  if uri.scheme == "http":
    return HttpConnectionRef(
      kind: HttpConnectionType.Nonsecure,
      transp: transp, reader: treader, writer: twriter
    )
  else:
    let tlsstream = newTLSClientAsyncStream(treader, twriter, uri.hostname,
                                            flags = flags)
    return HttpConnectionRef(
      kind: HttpConnectionType.Secure,
      transp: transp, reader: tlsstream.reader, writer: tlsstream.writer,
      treader: treader, twriter: twriter
    )

proc closeWait*(conn: HttpConnectionRef): Future[void] {.async.} =
  case conn.kind
  of HttpConnectionType.Nonsecure:
    await allFutures(conn.reader.closeWait(), conn.writer.closeWait())
    await conn.transp.closeWait()
  of HttpConnectionType.Secure:
    await allFutures(conn.reader.closeWait(), conn.writer.closeWait())
    await allFutures(conn.treader.closeWait(), conn.twriter.closeWait())
    await conn.transp.closeWait()

proc checkConnection*(conf: RestTesterConf, uri: Uri): Future[void] {.async.} =
  let timeFut = sleepAsync(conf.attemptTimeout.seconds)
  var sleepTime = 1000.milliseconds
  let hostname = uri.hostname & ":" & uri.port
  while true:
    if timeFut.finished():
      fatal "Connection with remote host could not be established in time",
            uri = uri.hostname, time = $conf.attemptTimeout.seconds
      raise newException(ConnectionError, "Unable to establish connection")

    let address =
      block:
        let res = uri.getAddress()
        if res.isErr():
          fatal "Unable to resolve remote host address", host = hostname
          raise newException(ConnectionError, "Unable to resolve address")
        else:
          res.get()

    let conn =
      try:
        await openConnection(address, uri, conf.getTLSFlags())
      except ConnectionError:
        notice "Unable to establish connection with remote host",
               host = hostname,
               sleep_until_next_attempt = $(((sleepTime * 3) div 2).seconds)
        nil

    if not(isNil(conn)):
      notice "Connection with remote host established", host = hostname
      await closeWait(conn)
      return

    if timeFut.finished():
      fatal "Connection with remote host could not be established in time",
            uri = hostname, time = $conf.attemptTimeout.seconds
      raise newException(ConnectionError, "Unable to establish connection")

    await sleepAsync(sleepTime)
    # Increasing sleep time by 50%.
    sleepTime = (sleepTime * 3) div 2

proc compact(v: string, size: int): string =
  let delim = "..."
  doAssert(size >= (len(delim) + 2))
  if len(v) <= size:
    v
  else:
    var length1 = (size - len(delim)) div 2
    var length2 = size - length1 - len(delim)
    if length1 < length2:
      swap(length1, length2)
    v[0 .. (length1 - 1)] & delim & v[len(v) - length2 .. ^1]

proc getTestName(rule: JsonNode): string =
  let request = rule.getOrDefault("request")
  if isNil(request):
    "[incorrect]"
  else:
    let juri = request.getOrDefault("url")
    if isNil(juri):
      "[incorrect]"
    else:
      compact(juri.str, 40)

proc prepareRequest(uri: Uri,
                    rule: JsonNode): Result[tuple[url: string, request: string],
                                            cstring] =
  let request = rule.getOrDefault("request")
  if isNil(request):
    return err("Missing `request` field")

  let meth =
    block:
      let jmethod = request.getOrDefault("method")
      if isNil(jmethod):
        "GET"
      else:
        if jmethod.kind != JString:
          return err("Field `method` should be string")
        jmethod.str

  let requestUri =
    block:
      let juri = request.getOrDefault("url")
      if isNil(juri):
        return err("Missing requests' `url`")
      else:
        if juri.kind != JString:
          return err("Field `url` should be string")
        juri.str

  let requestHeaders =
    block:
      var default: seq[tuple[key: string, value: string]]
      let jheaders = request.getOrDefault("headers")
      if isNil(jheaders):
        default
      else:
        var res: seq[tuple[key: string, value: string]]
        if jheaders.kind != JObject:
          return err("Field `headers` should be an object")
        for key, value in jheaders.fields:
          if value.kind != JString:
            return err("Field `headers` element should be only strings")
          res.add((key, value.str))
        res

  let (requestBodyType, requestBodyData) =
    block:
      let jbody = request.getOrDefault("body")
      if isNil(jbody):
        ("", "")
      else:
        if jbody.kind != JObject:
          return err("Field `body` should be object")
        let btype = jbody.getOrDefault("content-type")
        if isNil(btype):
          return err("Field `body.content-type` must be present")
        if btype.kind != JString:
          return err("Field `body.content-type` should be string")
        let bdata = jbody.getOrDefault("data")
        if isNil(bdata):
          return err("Field `body.data` must be present")
        if bdata.kind != JString:
          return err("Field `body.data` should be string")
        (btype.str, bdata.str)

  var res = meth & " " & uri.path & requestUri & " HTTP/1.1\r\n"
  res.add("Content-Length: " & Base10.toString(uint64(len(requestBodyData))) &
          "\r\n")

  if len(requestBodyType) > 0:
    res.add("Content-Type: " & requestBodyType & "\r\n")

  for item in requestHeaders:
    res.add(item.key & ": " & item.value & "\r\n")

  let (hostPresent, datePresent) =
    block:
      var flag1 = false
      var flag2 = false
      for item in requestHeaders:
        if cmpIgnoreCase(item.key, "host") == 0:
          flag1 = true
        elif cmpIgnoreCase(item.key, "date") == 0:
          flag2 = true
      (flag1, flag2)

  if not(hostPresent):
    res.add("Host: " & $uri.hostname & "\r\n")
  if not(datePresent):
    res.add("Date: " & httpDate() & "\r\n")
  res.add("\r\n")
  if len(requestBodyData) > 0:
    res.add(requestBodyData)
  ok((uri.path & requestUri, res))

proc getResponseStatusExpect(rule: JsonNode): Result[StatusExpect, cstring] =
  let response = rule.getOrDefault("response")
  if isNil(response):
    return err("Missing `response` field")
  let jstatus = response.getOrDefault("status")
  if isNil(jstatus):
    return err("Missing `response.status` field")

  let value =
    block:
      var res: seq[int]
      let jvalue = jstatus.getOrDefault("value")
      if isNil(jvalue):
        return err("Field `status.value` should be present")
      case jvalue.kind
      of JString:
        let nres = Base10.decode(uint16, jvalue.str)
        if nres.isErr():
          return err("Field `status.value` has incorrect value")
        res.add(int(nres.get()))
      of JInt:
        if jvalue.num < 0 or jvalue.num >= 1000:
          return err("Field `status.value` has incorrect value")
        res.add(int(jvalue.num))
      of JArray:
        if len(jvalue.elems) == 0:
          return err("Field `status.value` has an empty array")
        for jitem in jvalue.elems:
          let iitem =
            case jitem.kind
            of JString:
              let nres = Base10.decode(uint16, jitem.str)
              if nres.isErr():
                return err("Field `status.value` element has incorrect value")
              int(nres.get())
            of JInt:
              if jitem.num < 0 or jitem.num >= 1000:
                return err("Field `status.value` element has incorrect value")
              int(jitem.num)
            else:
              return err("Field `status.value` has incorrect elements")
          res.add(iitem)
      else:
        return err("Field `status.value` should be an array, string or integer")
      res

  let kind =
    block:
      let joperator = jstatus.getOrDefault("operator")
      if isNil(joperator):
        if len(value) > 1:
          StatusOperatorKind.OneOf
        else:
          StatusOperatorKind.Equals
      else:
        if joperator.kind != JString:
          return err("Field `status.operator` should be string")
        case toLowerAscii(joperator.str)
        of "equals":
          StatusOperatorKind.Equals
        of "oneof":
          StatusOperatorKind.OneOf
        of "insideoreq":
          StatusOperatorKind.InsideOrEq
        of "inside":
          StatusOperatorKind.Inside
        else:
          return err("Field `status.operator` has unknown or empty value")

  ok(StatusExpect(kind: kind, value: value))

proc getResponseHeadersExpect(rule: JsonNode): Result[HeadersExpect, cstring] =
  let response = rule.getOrDefault("response")
  if isNil(response):
    return err("Missing `response` field")
  let jheaders = response.getOrDefault("headers")
  if isNil(jheaders):
    return ok(HeadersExpect())
  if jheaders.kind != JArray:
    return err("`response.headers` should be array")
  if len(jheaders.elems) == 0:
    return ok(HeadersExpect())
  var res: seq[HeaderExpect]
  for jitem in jheaders.elems:
    if jitem.kind != JObject:
      return err("`response.headers` elements should be objects")
    let jkey = jitem.getOrDefault("key")
    if isNil(jkey) or jkey.kind != JString:
      continue
    let key = jkey.str
    let operator =
      block:
        let jop = jitem.getOrDefault("operator")
        if isNil(jop) or jop.kind != JString:
          HeaderOperatorKind.Exists
        else:
          case toLowerAscii(jop.str)
          of "exists":
            HeaderOperatorKind.Exists
          of "notexists":
            HeaderOperatorKind.NotExists
          of "equals":
            HeaderOperatorKind.Equals
          of "oneof":
            HeaderOperatorKind.OneOf
          of "substr":
            HeaderOperatorKind.Substr
          else:
            return err("`response.header` element has incorrect operator")
    let value =
      block:
        var vres: seq[string]
        let jvalue = jitem.getOrDefault("value")
        if not isnil(jvalue):
          case jvalue.kind
          of JArray:
            if len(jvalue.elems) == 0:
              return err("`response.header` element has an empty array value")
            for jelem in jvalue.elems:
              case jelem.kind
              of JString:
                vres.add(jelem.str)
              of JInt:
                vres.add(Base10.toString(uint64(jvalue.num)))
              else:
                return err("`response.header` element has incorrect value")
          of JString:
            vres.add(jvalue.str)
          of JInt:
            vres.add(Base10.toString(uint64(jvalue.num)))
          else:
            return err("`response.header` element has incorrect value")
        vres
    res.add(HeaderExpect(key: key, value: value, kind: operator))
  ok(HeadersExpect(headers: res))

proc getResponseBodyExpect(rule: JsonNode): Result[BodyExpect, cstring] =
  let response = rule.getOrDefault("response")
  if isNil(response):
    return err("Missing `response` field")
  let jbody = response.getOrDefault("body")
  if isNil(jbody):
    return ok(BodyExpect())
  if jbody.kind != JArray:
    return err("`response.body` should be array")
  if len(jbody.elems) == 0:
    return ok(BodyExpect())

  var res: seq[BodyItemExpect]

  for jitem in jbody.elems:
    if jitem.kind != JObject:
      return err("`response.body` elements should be objects")

    let operator =
      block:
        let jop = jitem.getOrDefault("operator")
        if isNil(jop) or jop.kind != JString:
          BodyOperatorKind.Exists
        else:
          case toLowerAscii(jop.str)
          of "exists":
            BodyOperatorKind.Exists
          of "jstructcmps":
            BodyOperatorKind.JsonStructCmpS
          of "jstructcmpns":
            BodyOperatorKind.JsonStructCmpNS
          of "jstructcmpsav":
            BodyOperatorKind.JsonStructCmpSAV
          of "jstructcmpnsav":
            BodyOperatorKind.JsonStructCmpNSAV
          else:
            return err("`response.body` element has incorrect operator")

    case operator
    of BodyOperatorKind.Exists:
      res.add(BodyItemExpect(kind: operator))
    of BodyOperatorKind.JsonStructCmpS, BodyOperatorKind.JsonStructCmpNS,
       BodyOperatorKind.JsonStructCmpSAV, BodyOperatorKind.JsonStructCmpNSAV:
      let start =
        block:
          var default: seq[string]
          var rstart: seq[string]
          let jstart = jitem.getOrDefault("start")
          if isNil(jstart):
            default
          else:
            case jstart.kind
            of JString:
              rstart.add(jstart.str)
            of JArray:
              if len(jstart.elems) != 0:
                for elem in jstart.elems:
                  case elem.kind
                  of JString:
                    rstart.add(elem.str)
                  else:
                    return err("`response.body` element has incorrect `start`" &
                               " option")
            else:
              return err("`response.body` element has incorrect `start` option")
            rstart
      let body =
        block:
          let jvalue = jitem.getOrDefault("value")
          if jvalue.isNil():
            return err("`response.body` element has incorrect `value` option")
          jvalue
      res.add(BodyItemExpect(kind: operator, startPath: start, value: body))
  ok(BodyExpect(items: res))

proc validateStatus(status: int, expect: StatusExpect): bool =
  case expect.kind
  of StatusOperatorKind.Equals:
    expect.value[0] == status
  of StatusOperatorKind.OneOf:
    status in expect.value
  of StatusOperatorKind.InsideOrEq:
    if len(expect.value) < 2:
      status >= expect.value[0]
    else:
      status >= expect.value[0] and status <= expect.value[1]
  of StatusOperatorKind.Inside:
    if len(expect.value) < 2:
      status > expect.value[0]
    else:
      status > expect.value[0] and status < expect.value[1]

proc validateHeaders(resp: HttpResponseHeader, expect: HeadersExpect): bool =
  if len(expect.headers) == 0:
    true
  else:
    for item in expect.headers:
      case item.kind
      of HeaderOperatorKind.Exists:
        if item.key notin resp:
          return false
      of HeaderOperatorKind.NotExists:
        if item.key in resp:
          return false
      of HeaderOperatorKind.Equals:
        if item.key notin resp:
          return false
        let v = resp[item.key]
        if cmpIgnoreCase(v, item.value[0]) != 0:
          return false
      of HeaderOperatorKind.OneOf:
        if item.key notin resp:
          return false
        let v = resp[item.key]
        var r = false
        for citem in item.value:
          if cmpIgnoreCase(citem, v) == 0:
            r = true
            break
        if not(r):
          return false
      of HeaderOperatorKind.Substr:
        if item.key notin resp:
          return false
        let v = resp[item.key]
        if strutils.find(v, item.value[0]) < 0:
          return false
    true

proc jsonBody(body: openArray[byte]): Result[JsonNode, cstring] =
  var sbody = cast[string](@body)
  let res =
    try:
      parseJson(sbody)
    except CatchableError:
      return err("Unable to parse json")
    except Exception as exc:
      raiseAssert exc.msg
  ok(res)

proc getPath(jobj: JsonNode, path: seq[string]): Result[JsonNode, cstring] =
  var jnode = jobj
  for item in path:
    let jitem = jnode.getOrDefault(item)
    if isNil(jitem):
      return err("Path not found")
    jnode = jitem
  ok(jnode)

proc structCmp(j1, j2: JsonNode, strict: bool, checkvalue: bool): bool =
  if j1.kind != j2.kind:
    return false
  case j1.kind
  of JArray:
    # In case of array we checking first element of `expect` with all the
    # elements in `result`.
    if len(j1.elems) == 0:
      true
    else:
      if len(j2.elems) == 0:
        false
      else:
        for item in j1.elems:
          if not(structCmp(item, j2.elems[0], strict, checkvalue)):
            return false
        true
  of JObject:
    if strict:
      if len(j1.fields) != len(j2.fields):
        return false
      for key, value in j1.fields:
        let j2node = j2.getOrDefault(key)
        if isNil(j2node):
          return false
        if not(structCmp(value, j2node, strict, checkvalue)):
          return false
      true
    else:
      for key, value in j2.fields:
        let j1node = j1.getOrDefault(key)
        if isNil(j1node):
          return false
        if not(structCmp(j1node, value, strict, checkvalue)):
          return false
      true
  of JString:
    if checkvalue: j1.str == j2.str else: true
  of JInt:
    if checkvalue: j1.num == j2.num else: true
  of JFloat:
    if checkvalue: j1.fnum == j2.fnum else: true
  of JBool:
    if checkvalue: j1.bval == j2.bval else: true
  of JNull:
    true

proc validateBody(body: openArray[byte], expect: BodyExpect): bool =
  if len(expect.items) == 0:
    true
  else:
    for item in expect.items:
      case item.kind
      of BodyOperatorKind.Exists:
        if len(body) == 0:
          return false
      of BodyOperatorKind.JsonStructCmpS, BodyOperatorKind.JsonStructCmpNS,
         BodyOperatorKind.JsonStructCmpSAV, BodyOperatorKind.JsonStructCmpNSAV:
        let jbody =
          block:
            let jres = jsonBody(body)
            if jres.isErr():
              return false
            let jnode = jres.get()
            let jpathres = jnode.getPath(item.startPath)
            if jpathres.isErr():
              return false
            jpathres.get()
        let strict =
          if item.kind in {BodyOperatorKind.JsonStructCmpS,
                           BodyOperatorKind.JsonStructCmpSAV}:
            true
          else:
            false
        let checkvalue =
          if item.kind in {BodyOperatorKind.JsonStructCmpSAV,
                           BodyOperatorKind.JsonStructCmpNSAV}:
            true
          else:
            false
        if not(structCmp(jbody, item.value, strict, checkvalue)):
          return false
    true

proc failure(t: typedesc[TestResult], code: TestResultKind,
              message: string = "",
              flags: set[TestResultFlag] = {},
              times: array[4, Duration]): TestResult =
  TestResult(kind: code, message: message, flags: flags, times: times)

proc success(t: typedesc[TestResult], times: array[4, Duration]): TestResult =
  TestResult(kind: TestResultKind.ValidationSuccess, times: times)

proc runTest(conn: HttpConnectionRef, uri: Uri,
             rule: JsonNode, workerIndex: int,
             testIndex: int): Future[TestResult] {.async.} =
  var times: array[4, Duration]
  let testName = rule.getTestName()
  let testPath = uri.path & rule.getTestName()

  debug "Running test", name = testName, test_index = testIndex,
                        worker_index = workerIndex

  let (_, request) =
    block:
      let res = prepareRequest(uri, rule)
      if res.isErr():
        return TestResult.failure(TestResultKind.RuleError,
                                  "Could not read request data: " &
                                  $res.error(), times = times)
      res.get()

  let statusExpect =
    block:
      let res = getResponseStatusExpect(rule)
      if res.isErr():
        return TestResult.failure(TestResultKind.RuleError,
                                  "Could not read response status data: " &
                                  $res.error(), times = times)
      res.get()

  let headersExpect =
    block:
      let res = getResponseHeadersExpect(rule)
      if res.isErr():
        return TestResult.failure(TestResultKind.RuleError,
                                  "Could not read response headers data: " &
                                  $res.error(), times = times)
      res.get()

  let bodyExpect =
    block:
      let res = getResponseBodyExpect(rule)
      if res.isErr():
        return TestResult.failure(TestResultKind.RuleError,
                                  "Could not read response body data: " &
                                  $res.error(), times = times)
      res.get()

  let testSm = Moment.now()
  var headersBuf = newSeq[byte](8192)
  var dataBuf = newSeq[byte](8192)

  try:
    let sm = Moment.now()
    await conn.writer.write(request)
    times[0] = Moment.now() - sm
    debug "Request sent", name = testName,
                          elapsed = $times[0], test_index = testIndex,
                          worker_index = workerIndex
  except AsyncStreamError:
    return TestResult.failure(TestResultKind.WriteRequestError,
                              "Unable to send request", {ResetConnection},
                              times)
  let rlen =
    try:
      let sm = Moment.now()
      let res = await conn.reader.readUntil(addr headersBuf[0],
                                            len(headersBuf), HeadersMark)
      times[1] = Moment.now() - sm
      debug "Response headers received", name = testName,
                                         length = res, elapsed = $times[1],
                                         test_index = testIndex,
                                         worker_index = workerIndex
      res
    except AsyncStreamError:
      return TestResult.failure(TestResultKind.ReadResponseHeadersError,
                                "Unable to read response headers",
                                {ResetConnection}, times)

  headersBuf.setLen(rlen)

  let resp = parseResponse(headersBuf, true)
  if not(resp.success()):
    return TestResult.failure(TestResultKind.ResponseError,
                              "Response headers could not be parsed",
                              {ResetConnection}, times)

  if "Content-Length" notin resp:
    return TestResult.failure(TestResultKind.ResponseError,
                              "Content-Length header must be present",
                              {ResetConnection}, times)
  let contentLength = resp.contentLength()
  if contentLength < 0:
    return TestResult.failure(TestResultKind.ResponseError,
                              "Content-Length value is incorrect",
                              {ResetConnection}, times)
  else:
    # TODO: We are not checking Content-Length size here
    if contentLength > 0:
      dataBuf.setLen(contentLength)
      try:
        let sm = Moment.now()
        await conn.reader.readExactly(addr dataBuf[0], len(dataBuf))
        times[2] = Moment.now() - sm
        debug "Response body received", length = len(dataBuf),
              name = testName,
              elapsed = $times[2], test_index = testIndex,
              worker_index = workerIndex
      except AsyncStreamError:
        return TestResult.failure(TestResultKind.ReadResponseBodyError,
                                  "Unable to read response body",
                                  {ResetConnection}, times)
    else:
      debug "Response body is missing", name = testName, path = testPath
      dataBuf.setLen(0)

    let res1 = validateStatus(resp.code, statusExpect)
    let res2 = validateHeaders(resp, headersExpect)
    let res3 = validateBody(dataBuf, bodyExpect)
    times[3] = Moment.now() - testSm

    if res1 and res2 and res3:
      return TestResult.success(times)
    else:
      let flags =
        block:
          var res: set[TestResultFlag]
          if not(res1):
            res.incl(StatusValidationFailure)
          if not(res2):
            res.incl(HeadersValidationFailure)
          if not(res3):
            res.incl(BodyValidationFailure)
          res
      return TestResult.failure(TestResultKind.ValidationError, times = times,
                                flags = flags)

proc workerLoop(address: TransportAddress, uri: Uri, worker: int,
                conf: RestTesterConf,
                inputQueue: AsyncQueue[TestCase],
                outputQueue: AsyncQueue[TestCaseResult]) {.async.} =
  let hostname = uri.hostname & ":" & uri.port
  var conn: HttpConnectionRef = nil
  var index: int
  debug "Test worker has been started", worker = worker
  while true:
    try:
      let test = await inputQueue.popFirst()
      index = test.index
      if isNil(conn):
        conn = await openConnection(address, uri, conf.getTLSFlags())
        debug "Opened new connection with remote host", address = $address,
              worker = worker
      let testRes = await runTest(conn, uri, test.rule, worker, test.index)
      let caseRes = TestCaseResult(index: test.index, data: testRes)
      await outputQueue.addLast(caseRes)
      await conn.closeWait()
      conn = nil
      index = 0
    except CancelledError:
      if not(isNil(conn)):
        await conn.closeWait()
        conn = nil
      notice "Got signal, exiting", worker = worker
      return
    except ConnectionError:
      warn "Unable to establish connection with remote host", host = hostname,
           worker = worker
      return
    except CatchableError as exc:
      warn "Unexpected exception while running test test run", host = hostname,
           error_name = exc.name, error_msg = exc.msg, index = index,
           worker = worker
      return

proc startTests(conf: RestTesterConf, uri: Uri,
                rules: seq[JsonNode]): Future[int] {.async.} =
  var workers = newSeq[Future[void]](conf.connectionsCount)
  var inputQueue = newAsyncQueue[TestCase](len(rules))
  var outputQueue = newAsyncQueue[TestCaseResult](conf.connectionsCount)
  var results = newSeq[TestResult](len(rules))
  var restarts = 0

  let address =
    block:
      let res = uri.getAddress()
      if res.isErr():
        fatal "Unable to resolve remote host address, exiting",
              uri = $uri
        return 1
      res.get()

  for index, item in rules:
    inputQueue.addLastNoWait(TestCase(index: index, rule: item))

  for i in 0 ..< len(workers):
    workers[i] = workerLoop(address, uri, i, conf, inputQueue, outputQueue)

  block:
    var pending = newSeq[FutureBase](len(workers) + 1)
    for i in 0 ..< len(workers):
      pending[i] = workers[i]

    var fut: Future[TestCaseResult]
    for i in 0 ..< len(rules):
      fut = outputQueue.popFirst()
      pending[^1] = fut
      discard await race(pending)
      for i in 0 ..< len(pending):
        if pending[i].finished():
          if i < len(workers):
            warn "Test worker quits unexpectedly", index = i, restarts = restarts
            return 1
          else:
            if pending[i].failed() or pending[i].cancelled():
              warn "Unexpected result from queue"
              return 1

            let tcaseRes = fut.read()
            results[tcaseRes.index] = tcaseRes.data
            notice "Got test result", name = rules[tcaseRes.index].getTestName(),
                                      index = tcaseRes.index,
                                      value = tcaseRes.data.kind
            pending[i] = nil

  debug "Stopping workers"
  # Stopping  workers
  block:
    var pending = newSeq[Future[void]]()
    for worker in workers:
      if not(worker.finished()):
        pending.add(worker.cancelAndWait())
    await allFutures(pending)

  var errCode = 0
  let headerLine = "\r\n" &
    '-'.repeat(45 + 20 + 7 + 20 + 20) & "\r\n" &
    alignLeft("TEST", 45) & alignLeft("STATUS", 20) &
    alignLeft("ERROR", 7) & alignLeft("ELAPSED", 20) &
    alignLeft("MESSAGE", 20) & "\r\n" &
    '-'.repeat(45 + 20 + 7 + 20 + 20)
  echo headerLine
  for index, item in rules:
    let errorFlag =
      block:
        var tmp = "---"
        if StatusValidationFailure in results[index].flags:
          tmp[0] = 'S'
        if HeadersValidationFailure in results[index].flags:
          tmp[1] = 'H'
        if BodyValidationFailure in results[index].flags:
          tmp[2] = 'R'
        tmp
    let line =
      alignLeft(item.getTestName() & "#" & $index, 45) &
      alignLeft($results[index].kind, 20) &
      alignLeft(errorFlag, 7) &
      alignLeft($results[index].times[3], 20) &
      alignLeft($results[index].message, 20)
    echo line
    if results[index].kind != ValidationSuccess:
      errCode = 1
  return errCode

proc run(conf: RestTesterConf): int =
  let uri =
    block:
      let res = conf.getUri()
      if res.isErr():
        fatal "Incomplete/incorrect URL", url = conf.url,
              error_msg = $res.error()
        return 1
      res.get()

  let jnodes =
    block:
      let res = conf.getTestRules()
      if res.isErr():
        fatal "Incomplete/incorrect rules file", file = conf.rulesFilename
        return 1
      res.get()

  notice "Waiting for initial connection attempt", time = conf.delayTime
  try:
    waitFor(sleepAsync(conf.delayTime.seconds))
  except CatchableError as exc:
    fatal "Unexpected test failure", error_name = exc.name, error_msg = exc.msg
    return 1

  notice "Exploring remote server hostname",
         hostname = uri.hostname & ":" & uri.port
  try:
    waitFor(checkConnection(conf, uri))
  except ConnectionError:
    return 1

  try:
    return waitFor(startTests(conf, uri, jnodes))
  except CatchableError as exc:
    fatal "Unexpected test failure", error_name = exc.name, error_msg = exc.msg
    return 1

when isMainModule:
  echo RestTesterHeader
  var conf = RestTesterConf.load(version = RestTesterVersion)
  quit run(conf)
