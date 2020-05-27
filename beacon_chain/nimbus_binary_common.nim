# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Common routines for a BeaconNode and a ValidatorClient

import
  # Standard library
  tables, random, strutils,

  # Nimble packages
  chronos,
  chronicles, chronicles/helpers as chroniclesHelpers,

  # Local modules
  spec/[datatypes, crypto], eth2_network

proc setupMainProc*(logLevel: string) =
  when compiles(defaultChroniclesStream.output.writer):
    defaultChroniclesStream.output.writer =
      proc (logLevel: LogLevel, msg: LogOutputStr) {.gcsafe, raises: [Defect].} =
        try:
          stdout.write(msg)
        except IOError as err:
          logLoggingFailure(cstring(msg), err)

  randomize()

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

template ctrlCHandling*(extraCode: untyped) =
  ## Ctrl+C handling
  proc controlCHandler() {.noconv.} =
    when defined(windows):
      # workaround for https://github.com/nim-lang/Nim/issues/4057
      setupForeignThreadGc()
    info "Shutting down after having received SIGINT"
    extraCode
  setControlCHook(controlCHandler)

template makeBannerAndConfig*(clientId: string, ConfType: type): untyped =
  let banner = clientId & "\p" & copyrights & "\p\p" & nimBanner
  ConfType.load(version = banner, copyrightBanner = banner)
