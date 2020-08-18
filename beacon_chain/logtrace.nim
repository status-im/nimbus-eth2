# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import confutils, json, times, streams, os, strutils, options, chronicles,
       tables, sequtils
import json_serialization

const
  LogTraceName* = "Beacon-Chain LogTrace Tool"
  LogTraceMajor*: int = 0
  LogTraceMinor*: int = 0
  LogTracePatch*: int = 4
  LogTraceVersion* = $LogTraceMajor & "." & $LogTraceMinor & "." &
                      $LogTracePatch
  LogTraceCopyright* = "Copyright(C) 2020" &
                       " Status Research & Development GmbH"
  LogTraceHeader* = LogTraceName & ", Version " & LogTraceVersion &
                    " [" & hostOS & ": " & hostCPU & "]\r\n" &
                    LogTraceCopyright & "\r\n"

type
  StartUpCommand* {.pure.} = enum
    pubsub, asl, asr, lat

  LogTraceConf* = object
    logFiles* {.
      desc: "Specifies one or more log files",
      abbr: "f",
      name: "log-file" }: seq[string]

    simDir* {.
      desc: "Specifies path to eth2_network_simulation directory",
      name: "sim-dir",
      defaultValue: "" }: string

    netDir* {.
      desc: "Specifies path to network build directory",
      name: "net-dir",
      defaultValue: "" }: string

    logDir* {.
      desc: "Specifies path with bunch of logs",
      name: "log-dir",
      defaultValue: "" }: string

    ignoreSerializationErrors* {.
      desc: "Ignore serialization errors while parsing log files",
      name: "ignore-errors",
      defaultValue: true }: bool

    dumpSerializationErrors* {.
      desc: "Dump full serialization errors while parsing log files",
      name: "dump-errors",
      defaultValue: false }: bool

    nodes* {.
      desc: "Specifies node names which logs will be used",
      name: "nodes" }: seq[string]

    allowedLag* {.
      desc: "Allowed latency lag multiplier",
      name: "lag",
      defaultValue: 2.0 }: float

    case cmd* {.command.}: StartUpCommand
    of pubsub:
      discard
    of asl:
      discard
    of asr:
      discard
    of lat:
      discard

  GossipDirection* = enum
    None, Incoming, Outgoing

  NodeDirectory* = object
    name*: string
    path*: string
    logs*: seq[string]

  LogMessage* = object of RootObj
    level* {.serializedFieldName: "lvl" .}: string
    timestamp* {.serializedFieldName: "ts" .}: DateTime
    msg*: string
    topics*: string
    tid*: int

  SlotStartMessage* = object of LogMessage
    beaconTime*: uint64
    finalizedEpoch*: uint64
    finalizedRoot*: string
    finalizedSlot*: uint64
    headEpoch*: uint64
    headRoot*: string
    headSlot*: uint64
    lastSlot*: uint64
    peers*: uint64
    scheduledSlot*: uint64

  AttestationDataObject* = object
    slot*: uint64
    index*: uint64
    beaconBlockRoot* {.serializedFieldName: "beacon_block_root".}: string
    sourceEpoch* {.serializedFieldName: "source_epoch".}: uint64
    sourceRoot* {.serializedFieldName: "source_root".}: string
    targetEpoch* {.serializedFieldName: "target_epoch".}: uint64
    targetRoot* {.serializedFieldName: "target_root".}: string

  AttestationObject* = object
    aggregationBits* {.serializedFieldName: "aggregation_bits".}: string
    data*: AttestationDataObject
    signature*: string

  AttestationSentMessage* = object of LogMessage
    attestation*: AttestationObject
    indexInCommittee*: uint64
    validator*: string

  AttestationReceivedMessage* = object of LogMessage
    attestation*: AttestationObject
    head*: string
    wallSlot*: uint64
    pcs*: string

  GossipMessage* = object
    kind*: GossipDirection
    id*: string
    datetime*: DateTime
    processed*: bool

  SaMessageType* {.pure.} = enum
    AttestationSent, SlotStart

  SRMessageType* {.pure.} = enum
    AttestationSent, AttestationReceived

  SlotAttMessage* = object
    case kind*: SaMessageType
    of SaMessageType.AttestationSent:
      asmsg*: AttestationSentMessage
    of SaMessageType.SlotStart:
      ssmsg*: SlotStartMessage

  SRAttMessage* = object
    case kind*: SRMessageType
    of SRMessageType.AttestationSent:
      asmsg*: AttestationSentMessage
    of SRMessageType.AttestationReceived:
      armsg*: AttestationReceivedMessage

  SRANode* = object
    directory*: NodeDirectory
    sends*: seq[AttestationSentMessage]
    recvs*: TableRef[string, AttestationReceivedMessage]

proc readValue*(reader: var JsonReader, value: var DateTime) =
  let s = reader.readValue(string)
  try:
    value = parse(s, "YYYY-MM-dd HH:mm:ss'.'fffzzz", utc())
  except CatchableError:
    raiseUnexpectedValue(reader, "Invalid date time")

proc init(t: typedesc[GossipMessage], kind: GossipDirection, id,
          datestr: string): GossipMessage =
  GossipMessage(
    kind: kind,
    id: id,
    datetime: parse(datestr, "YYYY-MM-dd HH:mm:ss'.'fffzzz")
  )

proc `$`*(msg: GossipMessage): string =
  result = msg.id

proc readLogFile(file: string): seq[JsonNode] =
  var res = newSeq[JsonNode]()
  var stream = newFileStream(file)
  try:
    while not(stream.atEnd()):
      var line = stream.readLine()
      let node = parseJson(line)
      res.add(node)
    result = res
  except CatchableError as exc:
    warn "Error reading JSON data from file", file = file,
         errorMsg = exc.msg
  finally:
    stream.close()

proc readLogFileForAttsMessages(file: string,
                                ignoreErrors = true,
                                dumpErrors = false): seq[SlotAttMessage] =
  var res = newSeq[SlotAttMessage]()
  var stream = newFileStream(file)
  var line: string
  var counter = 0
  try:
    while not(stream.atEnd()):
      line = stream.readLine()
      inc(counter)
      var m: LogMessage
      try:
        m = Json.decode(line, LogMessage, allowUnknownFields = true)
      except SerializationError as exc:
        if dumpErrors:
          error "Serialization error while reading file, ignoring", file = file,
                 line_number = counter, errorMsg = exc.formatMsg(line)
        else:
          error "Serialization error while reading file, ignoring", file = file,
                 line_number = counter
        if not(ignoreErrors):
          raise exc
        else:
          continue

      if m.msg == "Attestation sent":
        let am = Json.decode(line, AttestationSentMessage,
                             allowUnknownFields = true)
        let m = SlotAttMessage(kind: SaMessageType.AttestationSent,
                               asmsg: am)
        res.add(m)
      elif m.msg == "Slot start":
        let sm = Json.decode(line, SlotStartMessage,
                             allowUnknownFields = true)
        let m = SlotAttMessage(kind: SaMessageType.SlotStart,
                               ssmsg: sm)
        res.add(m)

      if counter mod 10_000 == 0:
        info "Processing file", file = extractFilename(file),
                                lines_processed = counter,
                                lines_filtered = len(res)
    result = res

  except CatchableError as exc:
    warn "Error reading data from file", file = file, errorMsg = exc.msg
  finally:
    stream.close()

proc readLogFileForASRMessages(file: string, srnode: var SRANode,
                               ignoreErrors = true, dumpErrors = false) =
  var stream = newFileStream(file)
  var line: string
  var counter = 0
  try:
    while not(stream.atEnd()):
      var m: LogMessage
      line = stream.readLine()
      inc(counter)
      try:
        m = Json.decode(line, LogMessage, allowUnknownFields = true)
      except SerializationError as exc:
        if dumpErrors:
          error "Serialization error while reading file, ignoring", file = file,
                 line_number = counter, errorMsg = exc.formatMsg(line)
        else:
          error "Serialization error while reading file, ignoring", file = file,
                 line_number = counter
        if not(ignoreErrors):
          raise exc
        else:
          continue

      if m.msg == "Attestation sent":
        let sm = Json.decode(line, AttestationSentMessage,
                             allowUnknownFields = true)
        srnode.sends.add(sm)
      elif m.msg == "Attestation received":
        let rm = Json.decode(line, AttestationReceivedMessage,
                             allowUnknownFields = true)
        discard srnode.recvs.hasKeyOrPut(rm.attestation.signature, rm)

      if counter mod 10_000 == 0:
        info "Processing file", file = extractFilename(file),
                                lines_processed = counter,
                                sends_filtered = len(srnode.sends),
                                recvs_filtered = len(srnode.recvs)

  except CatchableError as exc:
    warn "Error reading data from file", file = file, errorMsg = exc.msg
  finally:
    stream.close()

proc readLogFileForSecondMessages(file: string, ignoreErrors = true,
                                  dumpErrors = false): seq[LogMessage] =
  var stream = newFileStream(file)
  var line: string
  var counter = 0
  try:
    while not (stream.atEnd()):
      var m: LogMessage
      line = stream.readLine()
      inc(counter)
      try:
        m = Json.decode(line, LogMessage, allowUnknownFields = true)
      except SerializationError as exc:
        if dumpErrors:
          error "Serialization error while reading file, ignoring", file = file,
                 line_number = counter, errorMsg = exc.formatMsg(line)
        else:
          error "Serialization error while reading file, ignoring", file = file,
                 line_number = counter
        if not(ignoreErrors):
          raise exc
        else:
          continue
      if m.msg == "onSecond task completed":
        result.add(m)

      if counter mod 10_000 == 0:
        info "Processing file", file = extractFilename(file),
                                lines_processed = counter,
                                seconds_filtered = len(result)
  except CatchableError as exc:
    warn "Error reading data from file", file = file, errorMsg = exc.msg
  finally:
    stream.close()

proc filterGossipMessages(log: seq[JsonNode]): seq[GossipMessage] =
  # Because of times.DateTime object we forced to turn off [ProveInit] warnings
  # You can remove this pragmas when Nim compiler or times.nim will be fixed.
  {.push warning[ProveInit]: off.}
  result = newSeq[GossipMessage]()
  {.pop.}
  for node in log:
    if ("msg" in node) and ("message_id" in node) and ("ts" in node):
      let message = node["msg"].getStr()
      if message == "Incoming pubsub message received":
        let msg = GossipMessage.init(Incoming, node["message_id"].getStr(),
                                     node["ts"].getStr())
        result.add(msg)
      elif message == "Outgoing pubsub message has been sent":
        let msg = GossipMessage.init(Outgoing, node["message_id"].getStr(),
                                     node["ts"].getStr())
        result.add(msg)

iterator simDirectoryLogFiles*(simdir: string): string =
  let absPath = absolutePath(simdir)
  let dataPath = absPath & DirSep & "data"
  if not dirExists(dataPath):
    error "Invalid `eth2_network_simulation` data directory structure",
          path = dataPath
    quit(1)
  var index = 0
  while true:
    let path = dataPath & DirSep & "node-" & $index & DirSep
    let simplePath = path & "beacon_node.log"
    let bootPath = path & "bootstrap_node.log"
    if fileExists(simplePath):
      yield simplePath
    elif fileExists(bootPath):
      yield bootPath
    else:
      break
    inc(index)

proc getDirectoryLogFiles*(builddir: string,
                           filter: seq[string]): seq[NodeDirectory] =
  var res = newSeq[NodeDirectory]()
  let absPath = absolutePath(builddir)
  let dataPath = absPath & DirSep & "data"
  if not dirExists(dataPath):
    error "Invalid `network` data directory structure",
          path = dataPath
    quit(1)

  for dirPath in walkDirs(dataPath & DirSep & "*"):
    let name = extractFilename(dirPath)
    if (len(filter) == 0) or (name in filter):
      var nodeDir = NodeDirectory(name: extractFilename(dirPath),
                                  path: dirPath)
      for filePath in walkFiles(dirPath & DirSep & "*.log"):
        nodeDir.logs.add(extractFilename(filePath))
      if len(nodeDir.logs) > 0:
        res.add(nodeDir)
  return res

proc getLogFiles*(builddir: string,
                  filter: seq[string]): seq[NodeDirectory] =
  var res = newSeq[NodeDirectory]()
  let dataPath = absolutePath(builddir)
  if not dirExists(dataPath):
    error "Logs directory did not exist", path = dataPath
    quit(1)
  for filePath in walkFiles(dataPath & DirSep & "*.*"):
    let name = extractFilename(filePath)
    if (len(filter) == 0) or (name in filter):
      let nodeDir = NodeDirectory(name: extractFilename(filePath),
                                  path: dataPath,
                                  logs: @[extractFilename(filePath)])
      res.add(nodeDir)
  return res

proc getMessage(logs: seq[GossipMessage],
                msg: GossipMessage): Option[GossipMessage] =
  {.push warning[ProveInit]: off.}
  result = none[GossipMessage]()
  {.pop.}
  for i in 0 ..< len(logs):
    if logs[i].kind == Incoming and logs[i].id == msg.id:
      {.push warning[ProveInit]: off.}
      result = some(logs[i])
      {.pop.}

proc runPubsub(logConf: LogTraceConf, logFiles: seq[string]) =
  var logs = newSeq[tuple[name: string, data: seq[GossipMessage]]]()

  if len(logFiles) < 2:
    error "Number of log files are not enough to process pubsub messages",
          logs_count = len(logFiles)
    quit(1)

  for item in logFiles:
    let data = filterGossipMessages(readLogFile(item))
    logs.add((name: item, data: data))
    info "Loaded log file", logfile = item, lines_count = len(data)

  {.push warning[ProveInit]: off.}
  var checks = newSeq[Option[GossipMessage]](len(logs))
  {.pop.}

  var misses = 0
  for i in 0 ..< len(logs):
    info "Processing log file", logfile = logs[i].name
    for k in 0 ..< len(logs[i].data):
      let item = logs[i].data[k]
      if item.kind == Outgoing:
        info "Searching message", message_id = $item, logfile = logs[i].name
        checks[i] = some(item)
        for z in 1 ..< len(logs):
          let index = (i + z) mod len(logs)
          checks[index] = getMessage(logs[index].data, item)

        for z in 1 ..< len(checks):
          let index = (i + z) mod len(logs)
          if not(checks[index].isSome()):
            warn "Message not found in log", logfile = logs[index].name,
                                             message_id = $item
            inc(misses)

  if misses == 0:
    info "No missing messages found"
  else:
    warn "Number of missing messages found", count = $misses

proc runAttSend(logConf: LogTraceConf, logFiles: seq[string]) =
  info "Check for late `attestation sent` messages"
  if len(logFiles) < 1:
    error "Number of log files are not enough to process pubsub messages",
          logs_count = len(logFiles)
    quit(1)

  let minDuration = initDuration(seconds = 4)
  var slotMessagesCount = 0
  var attsMessagesCount = 0
  var lateAttsMessagesCount = 0

  for item in logFiles:
    info "Processing log file", logFile = item
    let data = readLogFileForAttsMessages(item,
                                          logConf.ignoreSerializationErrors,
                                          logConf.dumpSerializationErrors)

    var currentSlot: Option[SlotStartMessage]
    for item in data:
      if item.kind == SaMessageType.SlotStart:
        currentSlot = some(item.ssmsg)
        inc(slotMessagesCount)
      elif item.kind == SaMessageType.AttestationSent:
        if currentSlot.isSome():
          let attestationTime = currentSlot.get().timestamp -
                                item.asmsg.timestamp
          if attestationTime > minDuration:
            warn "Found an attestation that was sent later than necessary",
                 lateness = $attestationTime, slot = currentSlot.get(),
                 attestation = item.asmsg
            inc(lateAttsMessagesCount)
          inc(attsMessagesCount)
        else:
          warn "`Attestation sent` message appears before `Start slot` message",
               attestation = item.asmsg
  info "Check finished", attestation_sent_messages = attsMessagesCount,
                         slot_messages = slotMessagesCount,
                         late_attestation_messages = lateAttsMessagesCount

proc toSimple*(s: seq[string]): string =
  result = "[" & s.mapIt("'" & it & "'").join(", ") & "]"

proc runAttSendReceive(logConf: LogTraceConf, nodes: seq[NodeDirectory]) =
  info "Check for attestations send/receive messages"
  if len(nodes) < 2:
    error "Number of nodes' log files are not enough", nodes_count = len(nodes)
    quit(1)
  var srnodes = newSeq[SRANode]()

  for node in nodes:
    var srnode = SRANode(
      directory: node,
      sends: newSeq[AttestationSentMessage](),
      recvs: newTable[string, AttestationReceivedMessage]()
    )
    info "Processing node", node = node.name
    for logfile in node.logs:
      let path = node.path & DirSep & logfile
      info "Processing node's logfile", node = node.name, logfile = path
      readLogFileForASRMessages(path, srnode,
                                logConf.ignoreSerializationErrors,
                                logConf.dumpSerializationErrors)
    srnodes.add(srnode)

  if len(nodes) < 2:
    error "Number of nodes' log files are not enough", nodes_count = len(nodes)
    quit(1)

  for i in 0 ..< len(srnodes):
    var success = 0
    var failed = 0
    for item in srnodes[i].sends:
      var k = (i + 1) mod len(srnodes)
      var misses = newSeq[string]()
      while k != i:
        if item.attestation.signature notin srnodes[k].recvs:
          misses.add(srnodes[k].directory.name)
        k = (k + 1) mod len(srnodes)

      if len(misses) == 0:
        inc(success)
      else:
        inc(failed)
        info "Attestation was not received", sender = srnodes[i].directory.name,
             signature = item.attestation.signature,
             receivers = misses.toSimple(), send_stamp = item.timestamp

    info "Statistics for sender node", sender = srnodes[i].directory.name,
         successful_broadcasts = success, failed_broadcasts = failed,
         total_broadcasts = len(srnodes[i].sends)

proc runLatencyCheck(logConf: LogTraceConf, logFiles: seq[string],
                     nodes: seq[NodeDirectory]) =
  info "Check for async responsiveness"
  if len(nodes) == 0 and len(logFiles) == 0:
    error "Number of log files are not enough", nodes_count = len(nodes)
    quit(1)

  let allowedTime = int64(float(initDuration(seconds = 1).inMilliseconds()) *
                          logConf.allowedLag)

  for logFile in logFiles:
    info "Processing log file", logfile = logFile
    let msgs = readLogFileForSecondMessages(logFile,
                                            logConf.ignoreSerializationErrors,
                                            logConf.dumpSerializationErrors)
    var lastSecond: Option[LogMessage]
    var minEntry: Option[LogMessage]
    var maxEntry: Option[LogMessage]
    var minTime: times.Duration = initDuration(days = 1)
    var maxTime: times.Duration
    var sumMilliseconds: int64

    for item in msgs:
      if lastSecond.isNone():
        lastSecond = some(item)
      else:
        let time = item.timestamp - lastSecond.get().timestamp
        let start_time = lastSecond.get().timestamp
        let finish_time = item.timestamp
        if time.inMilliseconds() > allowedTime:
          info "Found time lag ",
               start_time = start_time.format("yyyy-MM-dd HH:mm:ss'.'fff"),
               finish_time = finish_time.format("yyyy-MM-dd HH:mm:ss'.'fff"),
               lag_time = time
        if time < minTime:
          minTime = time
          minEntry = some(item)
        if time > maxTime:
          maxTime = time
          maxEntry = some(item)
        sumMilliseconds += time.inMilliseconds()
        lastSecond = some(item)
    let avgTime = initDuration(milliseconds = sumMilliseconds div len(msgs))
    info "Latency statistics", min_time = minTime, max_time = maxTime,
                               avg_time = avgTime, seconds_count = len(msgs)

proc run(conf: LogTraceConf) =
  var logFiles: seq[string]
  var logNodes: seq[NodeDirectory]

  if len(conf.logFiles) > 0:
    for item in conf.logFiles:
      let absPath = absolutePath(item)
      if fileExists(absPath):
        logFiles.add(absPath)

  if len(conf.simDir) > 0:
    for item in simDirectoryLogFiles(conf.simDir):
      logFiles.add(item)
    logNodes = getDirectoryLogFiles(conf.simDir, conf.nodes)

  if len(conf.netDir) > 0:
    logNodes = getDirectoryLogFiles(conf.netDir, conf.nodes)

  if len(conf.logDir) > 0:
    logNodes = getLogFiles(conf.logDir, conf.nodes)

  if len(logFiles) == 0 and len(logNodes) == 0:
    error "Log file sources not specified or not enough log files found"
    quit(1)

  case conf.cmd
  of StartUpCommand.pubsub:
    runPubsub(conf, logFiles)
  of StartUpCommand.asl:
    runAttSend(conf, logFiles)
  of StartUpCommand.asr:
    runAttSendReceive(conf, logNodes)
  of StartUpCommand.lat:
    runLatencyCheck(conf, logFiles, logNodes)

when isMainModule:
  echo LogTraceHeader
  var conf = LogTraceConf.load(version = LogTraceVersion)
  run(conf)
