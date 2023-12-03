# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Common routines for a BeaconNode and a ValidatorClient

import
  # Standard library
  std/[tables, strutils, terminal, typetraits],

  # Nimble packages
  chronos, confutils, presto, toml_serialization, metrics,
  chronicles, chronicles/helpers as chroniclesHelpers, chronicles/topics_registry,
  stew/io2,

  # Local modules
  ./spec/[helpers, keystore],
  ./spec/datatypes/base,
  "."/[beacon_clock, beacon_node_status, conf, version]

when defined(posix):
  import termios

declareGauge versionGauge, "Nimbus version info (as metric labels)", ["version", "commit"], name = "version"
versionGauge.set(1, labelValues=[fullVersionStr, gitRevision])

declareGauge nimVersionGauge, "Nim version info", ["version", "nim_commit"], name = "nim_version"
nimVersionGauge.set(1, labelValues=[NimVersion, getNimGitHash()])

export
  confutils, toml_serialization, beacon_clock, beacon_node_status, conf

type
  SlotStartProc*[T] = proc(node: T, wallTime: BeaconTime,
                           lastSlot: Slot): Future[bool] {.gcsafe,
  raises: [].}

# silly chronicles, colors is a compile-time property
when defaultChroniclesStream.outputs.type.arity == 2:
  func stripAnsi(v: string): string =
    var
      res = newStringOfCap(v.len)
      i: int

    while i < v.len:
      let c = v[i]
      if c == '\x1b':
        var
          x = i + 1
          found = false

        while x < v.len: # look for [..m
          let c2 = v[x]
          if x == i + 1:
            if c2 != '[':
              break
          else:
            if c2 in {'0'..'9'} + {';'}:
              discard # keep looking
            elif c2 == 'm':
              i = x + 1
              found = true
              break
            else:
              break
          inc x

        if found: # skip adding c
          continue
      res.add c
      inc i

    res

proc updateLogLevel*(logLevel: string) {.raises: [ValueError].} =
  # Updates log levels (without clearing old ones)
  let directives = logLevel.split(";")
  try:
    setLogLevel(parseEnum[LogLevel](directives[0].capitalizeAscii()))
  except ValueError:
    raise (ref ValueError)(msg: "Please specify one of TRACE, DEBUG, INFO, NOTICE, WARN, ERROR or FATAL")

  if directives.len > 1:
    for topicName, settings in parseTopicDirectives(directives[1..^1]):
      if not setTopicState(topicName, settings.state, settings.logLevel):
        warn "Unrecognized logging topic", topic = topicName

proc detectTTY*(stdoutKind: StdoutLogKind): StdoutLogKind =
  if stdoutKind == StdoutLogKind.Auto:
    if isatty(stdout):
      # On a TTY, let's be fancy
      StdoutLogKind.Colors
    else:
      # When there's no TTY, we output no colors because this matches what
      # released binaries were doing before auto-detection was around and
      # looks decent in systemd-captured journals.
      StdoutLogKind.NoColors
  else:
    stdoutKind

when defaultChroniclesStream.outputs.type.arity == 2:
  from std/os import splitFile
  from "."/filepath import secureCreatePath

proc setupFileLimits*() =
  when not defined(windows):
    # In addition to databases and sockets, we need a file descriptor for every
    # validator - setting it to 16k should provide sufficient margin
    let
      limit = getMaxOpenFiles2().valueOr(16384)

    if limit < 16384:
      setMaxOpenFiles2(16384).isOkOr:
        warn "Cannot increase open file limit", err = osErrorMsg(error)

proc setupLogging*(
    logLevel: string, stdoutKind: StdoutLogKind, logFile: Option[OutFile]) =
  # In the cfg file for nimbus, we create two formats: textlines and json.
  # Here, we either write those logs to an output, or not, depending on the
  # given configuration.
  # Arguably, if we don't use a format, chronicles should not create it.

  when defaultChroniclesStream.outputs.type.arity != 2:
    warn "Logging configuration options not enabled in the current build"
  else:
    # Naive approach where chronicles will form a string and we will discard
    # it, even if it could have skipped the formatting phase

    proc noOutput(logLevel: LogLevel, msg: LogOutputStr) = discard
    proc writeAndFlush(f: File, msg: LogOutputStr) =
      try:
        f.write(msg)
        f.flushFile()
      except IOError as err:
        logLoggingFailure(cstring(msg), err)

    proc stdoutFlush(logLevel: LogLevel, msg: LogOutputStr) =
      writeAndFlush(stdout, msg)

    proc noColorsFlush(logLevel: LogLevel, msg: LogOutputStr) =
      writeAndFlush(stdout, stripAnsi(msg))

    let fileWriter =
      if logFile.isSome():
        let
          logFile = logFile.get.string
          logFileDir = splitFile(logFile).dir
          lres = secureCreatePath(logFileDir)
        if lres.isOk():
          try:
            let
              f = open(logFile, fmAppend)
              x = proc(logLevel: LogLevel, msg: LogOutputStr) =
                writeAndFlush(f, msg) # will close when program terminates
            x
          except CatchableError as exc:
            error "Failed to create log file", logFile, msg = exc.msg
            noOutput
        else:
          error "Failed to create directory for log file",
                path = logFileDir, err = ioErrorMsg(lres.error)
          noOutput
    else:
      noOutput

    defaultChroniclesStream.outputs[1].writer = fileWriter

    let tmp = detectTTY(stdoutKind)

    case tmp
    of StdoutLogKind.Auto: raiseAssert "checked above"
    of StdoutLogKind.Colors:
      defaultChroniclesStream.outputs[0].writer = stdoutFlush
    of StdoutLogKind.NoColors:
      defaultChroniclesStream.outputs[0].writer = noColorsFlush
    of StdoutLogKind.Json:
      defaultChroniclesStream.outputs[0].writer = noOutput

      let prevWriter = defaultChroniclesStream.outputs[1].writer
      defaultChroniclesStream.outputs[1].writer =
        proc(logLevel: LogLevel, msg: LogOutputStr) =
          stdoutFlush(logLevel, msg)
          prevWriter(logLevel, msg)
    of StdoutLogKind.None:
     defaultChroniclesStream.outputs[0].writer = noOutput

    if logFile.isSome():
      warn "The --log-file option is deprecated. Consider redirecting the standard output to a file instead"
  try:
    updateLogLevel(logLevel)
  except ValueError as err:
    try:
      stderr.write "Invalid value for --log-level. " & err.msg
    except IOError:
      echo "Invalid value for --log-level. " & err.msg
    quit 1

template makeBannerAndConfig*(clientId: string, ConfType: type): untyped =
  let
    version = clientId & "\p" & copyrights & "\p\p" &
      "eth2 specification v" & SPEC_VERSION & "\p\p" &
      nimBanner

  # TODO for some reason, copyrights are printed when doing `--help`
  {.push warning[ProveInit]: off.}
  let config = try:
    ConfType.load(
      version = version, # but a short version string makes more sense...
      copyrightBanner = clientId,
      secondarySources = proc (
          config: ConfType, sources: ref SecondarySources
      ) {.raises: [ConfigurationError].} =
        if config.configFile.isSome:
          sources.addConfigFile(Toml, config.configFile.get)
    )
  except CatchableError as err:
    # We need to log to stderr here, because logging hasn't been configured yet
    try:
      stderr.write "Failure while loading the configuration:\n"
      stderr.write err.msg
      stderr.write "\n"

      if err[] of ConfigurationError and
        err.parent != nil and
        err.parent[] of TomlFieldReadingError:
        let fieldName = ((ref TomlFieldReadingError)(err.parent)).field
        if fieldName in ["web3-url", "bootstrap-node",
                        "direct-peer", "validator-monitor-pubkey"]:
          stderr.write "Since the '" & fieldName & "' option is allowed to " &
                       "have more than one value, please make sure to supply " &
                       "a properly formatted TOML array\n"
    except IOError:
      discard
    quit 1
  {.pop.}
  config

proc checkIfShouldStopAtEpoch*(scheduledSlot: Slot,
                               stopAtEpoch: uint64): bool =
  # Offset backwards slightly to allow this epoch's finalization check to occur
  if scheduledSlot > 3 and stopAtEpoch > 0'u64 and
      (scheduledSlot - 3).epoch() >= stopAtEpoch:
    info "Stopping at pre-chosen epoch",
      chosenEpoch = stopAtEpoch,
      epoch = scheduledSlot.epoch(),
      slot = scheduledSlot
    true
  else:
    false

proc resetStdin*() =
  when defined(posix):
    # restore echoing, in case it was disabled by a password prompt
    let fd = stdin.getFileHandle()
    var attrs: Termios
    discard fd.tcGetAttr(attrs.addr)
    attrs.c_lflag = attrs.c_lflag or Cflag(ECHO)
    discard fd.tcSetAttr(TCSANOW, attrs.addr)

proc runKeystoreCachePruningLoop*(cache: KeystoreCacheRef) {.async.} =
  while true:
    let exitLoop =
      try:
        await sleepAsync(60.seconds)
        false
      except CatchableError:
        cache.clear()
        true
    if exitLoop: break
    cache.pruneExpiredKeys()

proc sleepAsync*(t: TimeDiff): Future[void] =
  sleepAsync(nanoseconds(
    if t.nanoseconds < 0: 0'i64 else: t.nanoseconds))

proc runSlotLoop*[T](node: T, startTime: BeaconTime,
                     slotProc: SlotStartProc[T]) {.async.} =
  var
    curSlot = startTime.slotOrZero()
    nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
    timeToNextSlot = nextSlot.start_beacon_time() - startTime

  info "Scheduling first slot action",
    startTime = shortLog(startTime),
    nextSlot = shortLog(nextSlot),
    timeToNextSlot = shortLog(timeToNextSlot)

  while true:
    # Start by waiting for the time when the slot starts. Sleeping relinquishes
    # control to other tasks which may or may not finish within the alotted
    # time, so below, we need to be wary that the ship might have sailed
    # already.
    await sleepAsync(timeToNextSlot)

    let
      wallTime = node.beaconClock.now()
      wallSlot = wallTime.slotOrZero() # Always > GENESIS!

    if wallSlot < nextSlot:
      # While we were sleeping, the system clock changed and time moved
      # backwards!
      if wallSlot + 1 < nextSlot:
        # This is a critical condition where it's hard to reason about what
        # to do next - we'll call the attention of the user here by shutting
        # down.
        fatal "System time adjusted backwards significantly - clock may be inaccurate - shutting down",
          nextSlot = shortLog(nextSlot),
          wallSlot = shortLog(wallSlot)
        bnStatus = BeaconNodeStatus.Stopping
        return

      # Time moved back by a single slot - this could be a minor adjustment,
      # for example when NTP does its thing after not working for a while
      warn "System time adjusted backwards, rescheduling slot actions",
        wallTime = shortLog(wallTime),
        nextSlot = shortLog(nextSlot),
        wallSlot = shortLog(wallSlot)

      # cur & next slot remain the same
      timeToNextSlot = nextSlot.start_beacon_time() - wallTime
      continue

    if wallSlot > nextSlot + SLOTS_PER_EPOCH:
      # Time moved forwards by more than an epoch - either the clock was reset
      # or we've been stuck in processing for a long time - either way, we will
      # skip ahead so that we only process the events of the last
      # SLOTS_PER_EPOCH slots
      warn "Time moved forwards by more than an epoch, skipping ahead",
        curSlot = shortLog(curSlot),
        nextSlot = shortLog(nextSlot),
        wallSlot = shortLog(wallSlot)

      curSlot = wallSlot - SLOTS_PER_EPOCH

    elif wallSlot > nextSlot:
        notice "Missed expected slot start, catching up",
          delay = shortLog(wallTime - nextSlot.start_beacon_time()),
          curSlot = shortLog(curSlot),
          nextSlot = shortLog(curSlot)

    let breakLoop = await slotProc(node, wallTime, curSlot)
    if breakLoop:
      break

    curSlot = wallSlot
    nextSlot = wallSlot + 1
    timeToNextSlot = nextSlot.start_beacon_time() - node.beaconClock.now()

proc init*(T: type RestServerRef,
           ip: IpAddress,
           port: Port,
           allowedOrigin: Option[string],
           validateFn: PatternCallback,
           config: AnyConf): T =
  let
    address = initTAddress(ip, port)
    serverFlags = {HttpServerFlags.QueryCommaSeparatedArray,
                   HttpServerFlags.NotifyDisconnect}
  # We increase default timeout to help validator clients who poll our server
  # at least once per slot (12.seconds).
  let
    headersTimeout =
      if config.restRequestTimeout == 0:
        chronos.InfiniteDuration
      else:
        seconds(int64(config.restRequestTimeout))
    maxHeadersSize = config.restMaxRequestHeadersSize * 1024
    maxRequestBodySize = config.restMaxRequestBodySize * 1024

  let res = RestServerRef.new(RestRouter.init(validateFn, allowedOrigin),
                              address, serverFlags = serverFlags,
                              httpHeadersTimeout = headersTimeout,
                              maxHeadersSize = maxHeadersSize,
                              maxRequestBodySize = maxRequestBodySize,
                              errorType = string)
  if res.isErr():
    notice "REST HTTP server could not be started", address = $address,
           reason = res.error()
    nil
  else:
    let server = res.get()
    notice "Starting REST HTTP server", url = "http://" & $server.localAddress()
    server

type
  KeymanagerInitResult* = object
    server*: RestServerRef
    token*: string

proc initKeymanagerServer*(
    config: AnyConf,
    existingRestServer: RestServerRef = nil): KeymanagerInitResult
    {.raises: [].} =

  var token: string
  let keymanagerServer = if config.keymanagerEnabled:
    if config.keymanagerTokenFile.isNone:
      echo "To enable the Keymanager API, you must also specify " &
           "the --keymanager-token-file option."
      quit 1

    let
      tokenFilePath = config.keymanagerTokenFile.get.string
      tokenFileReadRes = readAllChars(tokenFilePath)

    if tokenFileReadRes.isErr:
      fatal "Failed to read the keymanager token file",
            error = $tokenFileReadRes.error
      quit 1

    token = tokenFileReadRes.value.strip
    if token.len == 0:
      fatal "The keymanager token should not be empty", tokenFilePath
      quit 1

    when config is BeaconNodeConf:
      if existingRestServer != nil and
         config.restAddress == config.keymanagerAddress and
        config.restPort == config.keymanagerPort:
        existingRestServer
      else:
        RestServerRef.init(config.keymanagerAddress, config.keymanagerPort,
                           config.keymanagerAllowedOrigin,
                           validateKeymanagerApiQueries,
                           config)
    else:
      RestServerRef.init(config.keymanagerAddress, config.keymanagerPort,
                         config.keymanagerAllowedOrigin,
                         validateKeymanagerApiQueries,
                         config)
  else:
    nil

  KeymanagerInitResult(server: keymanagerServer, token: token)

proc quitDoppelganger*() =
  # Avoid colliding with
  # https://www.freedesktop.org/software/systemd/man/systemd.exec.html#Process%20Exit%20Codes
  # This error code is used to permanently shut down validators
  fatal "Doppelganger detection triggered! It appears a validator loaded into " &
    "this process is already live on the network - the validator is at high " &
    "risk of being slashed due to the same keys being used in two setups. " &
    "See https://nimbus.guide/doppelganger-detection.html for more information!"

  const QuitDoppelganger = 129
  quit QuitDoppelganger
