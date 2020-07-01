# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import confutils, json, times, streams, os, strutils, options, chronicles
import json_serialization

const
  LogTraceName* = "Beacon-Chain LogTrace Tool"
  LogTraceMajor*: int = 0
  LogTraceMinor*: int = 0
  LogTracePatch*: int = 1
  LogTraceVersion* = $LogTraceMajor & "." & $LogTraceMinor & "." &
                      $LogTracePatch
  LogTraceCopyright* = "Copyright(C) 2020" &
                       " Status Research & Development GmbH"
  LogTraceHeader* = LogTraceName & ", Version " & LogTraceVersion &
                    " [" & hostOS & ": " & hostCPU & "]\r\n" &
                    LogTraceCopyright & "\r\n"

type
  StartUpCommand* {.pure.} = enum
    pubsub, attest

  LogTraceConf* = object
    logFiles* {.
      desc: "Specifies one or more log files",
      abbr: "f",
      name: "log-file" }: seq[string]

    simDir* {.
      desc: "Specifies path to eth2_network_simulation directory",
      name: "sim-dir",
      defaultValue: "" }: string

    case cmd* {.command.}: StartUpCommand
    of pubsub:
      discard
    of attest:
      discard

  GossipDirection* = enum
    None, Incoming, Outgoing

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

  GossipMessage* = object
    kind*: GossipDirection
    id*: string
    datetime*: DateTime
    processed*: bool

  SaMessageType* = enum
    AttestationSent, SlotStart

  SlotAttMessage* = object
    case kind*: SaMessageType
    of SaMessageType.AttestationSent:
      asmsg*: AttestationSentMessage
    of SaMessageType.SlotStart:
      ssmsg*: SlotStartMessage

proc readValue*(reader: var JsonReader, value: var DateTime) =
  let s = reader.readValue(string)
  try:
    value = parse(s, "YYYY-MM-dd HH:mm:sszzz")
  except CatchableError:
    raiseUnexpectedValue(reader, "Invalid date time")

proc init(t: typedesc[GossipMessage], kind: GossipDirection, id,
          datestr: string): GossipMessage =
  result = GossipMessage(kind: kind, id: id,
                         datetime: parse(datestr, "YYYY-MM-dd HH:mm:sszzz"))

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

proc readLogFileForAttsMessages(file: string): seq[SlotAttMessage] =
  var res = newSeq[SlotAttMessage]()
  var stream = newFileStream(file)
  var line: string
  var counter = 0
  try:
    while not(stream.atEnd()):
      line = stream.readLine()
      let m = Json.decode(line, LogMessage, forwardCompatible = true)
      if m.msg == "Attestation sent":
        let am = Json.decode(line, AttestationSentMessage,
                             forwardCompatible = true)
        let m = SlotAttMessage(kind: SaMessageType.AttestationSent,
                               asmsg: am)
        res.add(m)
      elif m.msg == "Slot start":
        let sm = Json.decode(line, SlotStartMessage,
                             forwardCompatible = true)
        let m = SlotAttMessage(kind: SaMessageType.SlotStart,
                               ssmsg: sm)
        res.add(m)
      inc(counter)
      if counter mod 10_000 == 0:
         info "Processing file", file = file, lines_processed = counter,
                                 lines_filtered = len(res)
    result = res

  except SerializationError as exc:
    error "Serialization error while reading data from file", file = file,
          errorMsg = exc.formatMsg(line)
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
    let data = readLogFileForAttsMessages(item)

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

proc run(conf: LogTraceConf) =
  var logFiles: seq[string]

  if len(conf.logFiles) > 0:
    for item in conf.logFiles:
      let absPath = absolutePath(item)
      if fileExists(absPath):
        logFiles.add(absPath)

  if len(conf.simDir) > 0:
    for item in simDirectoryLogFiles(conf.simDir):
      logFiles.add(item)

  if len(logFiles) == 0:
    error "Log file sources not specified or not enough log files found"
    quit(1)

  if conf.cmd == StartUpCommand.pubsub:
    runPubsub(conf, logFiles)
  elif conf.cmd == StartUpCommand.attest:
    runAttSend(conf, logFiles)

when isMainModule:
  echo LogTraceHeader
  var conf = LogTraceConf.load(version = LogTraceVersion)
  run(conf)
