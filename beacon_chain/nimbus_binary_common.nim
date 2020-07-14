# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Common routines for a BeaconNode and a ValidatorClient

import
  # Standard library
  tables, random, strutils, os,

  # Nimble packages
  chronos, confutils/defs,
  chronicles, chronicles/helpers as chroniclesHelpers,

  # Local modules
  spec/[datatypes, crypto], eth2_network, time

proc setupLogging*(logLevel: string, logFile: Option[OutFile]) =
  when compiles(defaultChroniclesStream.output.writer):
    defaultChroniclesStream.outputs[0].writer =
      proc (logLevel: LogLevel, msg: LogOutputStr) {.gcsafe, raises: [Defect].} =
        try:
          stdout.write(msg)
        except IOError as err:
          logLoggingFailure(cstring(msg), err)

  randomize()

  if logFile.isSome:
    block openLogFile:
      let
        logFile = logFile.get.string
        logFileDir = splitFile(logFile).dir
      try:
        createDir logFileDir
      except CatchableError as err:
        error "Failed to create directory for log file", path = logFileDir, err = err.msg
        break openLogFile

      if not defaultChroniclesStream.outputs[1].open(logFile):
        error "Failed to create log file", logFile

  try:
    let directives = logLevel.split(";")
    try:
      setLogLevel(parseEnum[LogLevel](directives[0]))
    except ValueError:
      raise (ref ValueError)(msg: "Please specify one of TRACE, DEBUG, INFO, NOTICE, WARN, ERROR or FATAL")

    if directives.len > 1:
      for topicName, settings in parseTopicDirectives(directives[1..^1]):
        if not setTopicState(topicName, settings.state, settings.logLevel):
          warn "Unrecognized logging topic", topic = topicName
  except ValueError as err:
    stderr.write "Invalid value for --log-level. " & err.msg
    quit 1

template makeBannerAndConfig*(clientId: string, ConfType: type): untyped =
  let
    version = clientId & "\p" & copyrights & "\p\p" &
      "eth2 specification v" & SPEC_VERSION & "\p\p" &
      nimBanner
  # TODO for some reason, copyrights are printed when doing `--help`
  ConfType.load(
    version = version,
    copyrightBanner = clientId) # but a short version string makes more sense...

# TODO not sure if this belongs here but it doesn't belong in `time.nim` either
proc sleepToSlotOffset*(clock: BeaconClock, extra: chronos.Duration,
                        slot: Slot, msg: static string): Future[bool] {.async.} =
  let
    fromNow = clock.fromNow(slot.toBeaconTime(extra))

  if fromNow.inFuture:
    trace msg,
      slot = shortLog(slot),
      fromNow = shortLog(fromNow.offset),
      cat = "scheduling"

    await sleepAsync(fromNow.offset)
    return true
  return false
