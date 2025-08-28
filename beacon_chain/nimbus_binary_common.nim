# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Utilities common across several nimbus binaries (BN/VC/EC/Portal/etc)

import
  # Standard library
  std/[os, tables, terminal, typetraits],

  # Nimble packages
  chronos, confutils, presto, toml_serialization, metrics,
  chronicles, chronicles/helpers as chroniclesHelpers, chronicles/topics_registry,
  stew/io2, metrics/chronos_httpserver,

  # Local modules
  ./spec/keystore,
  ./buildinfo

when defaultChroniclesStream.outputs.type.arity == 2:
  from ./filepath import secureCreatePath

  import stew/staticfor

when defined(posix):
  import termios

export
  confutils, toml_serialization

type
  StdoutLogKind* {.pure.} = enum
    Auto = "auto"
    Colors = "colors"
    NoColors = "nocolors"
    Json = "json"
    None = "none"

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
    if getEnv("NO_COLOR").len == 0 and isatty(stdout):
      # On a TTY, let's be fancy
      StdoutLogKind.Colors
    else:
      # When there's no TTY, we output no colors because this matches what
      # released binaries were doing before auto-detection was around and
      # looks decent in systemd-captured journals.
      StdoutLogKind.NoColors
  else:
    stdoutKind

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
    proc noOutput(logLevel: LogLevel, msg: LogOutputStr) = discard
    proc writeAndFlush(f: File, msg: LogOutputStr) =
      try:
        f.write(msg)
        f.flushFile()
      except IOError as err:
        logLoggingFailure(cstring(msg), err)

    proc stdoutFlush(logLevel: LogLevel, msg: LogOutputStr) =
      writeAndFlush(stdout, msg)

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

    case detectTTY(stdoutKind)
    of StdoutLogKind.Auto:
      raiseAssert "Auto-detection done in detectTTY"
    of StdoutLogKind.Colors:
      defaultChroniclesStream.outputs[0].writer = stdoutFlush
      defaultChroniclesStream.outputs[0].colors = true
    of StdoutLogKind.NoColors:
      defaultChroniclesStream.outputs[0].writer = stdoutFlush
      defaultChroniclesStream.outputs[0].colors = false
    of StdoutLogKind.Json:
      defaultChroniclesStream.outputs[0].writer = noOutput

      let prevWriter = defaultChroniclesStream.outputs[1].writer
      defaultChroniclesStream.outputs[1].writer =
        proc(logLevel: LogLevel, msg: LogOutputStr) =
          stdoutFlush(logLevel, msg)
          prevWriter(logLevel, msg)
    of StdoutLogKind.None:
     defaultChroniclesStream.outputs[0].writer = noOutput

    staticFor i, 0..<defaultChroniclesStream.outputs.type.arity:
      setLogEnabled(defaultChroniclesStream.outputs[i].writer != noOutput, i)

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

proc makeBannerAndConfig*(
    helpBanner: string, versions: openArray[string],
    environment: openArray[string],
    ConfType: type,
): Result[ConfType, string] =
  let
    version = helpBanner & "\p" & copyrights & "\p\p" & (@versions & @[nimBanner()]).join("\p")

    cmdLine =
      if len(environment) == 0:
        commandLineParams()
      else:
        @environment

  {.push warning[ProveInit]: off.}
  let config =
    try:
      ConfType.load(
        version = version, # what --version outputs
        copyrightBanner = helpBanner, # what is shown on top of --help
        cmdLine = cmdLine,
        secondarySources = proc(
            config: ConfType, sources: ref SecondarySources
        ) {.raises: [ConfigurationError], gcsafe.} =
          if config.configFile.isSome:
            sources.addConfigFile(Toml, config.configFile.get)
        ,
      )
    except CatchableError as exc:
      # Logging not configured yet!
      var msg = "Failure while loading the configuration:\p" & exc.msg & "\p"
      if (exc[] of ConfigurationError) and not (isNil(exc.parent)) and
          (exc.parent[] of TomlFieldReadingError):
        let fieldName = ((ref TomlFieldReadingError)(exc.parent)).field
        if fieldName in
            [
              "el", "web3-url", "bootstrap-node", "direct-peer",
              "validator-monitor-pubkey",
            ]:
          msg &=
            "Since the '" & fieldName & "' option is allowed to " &
            "have more than one value, please make sure to supply " &
            "a properly formatted TOML array\p"
      return err(msg)
  {.pop.}
  ok(config)

template makeBannerAndConfig*(helpBanner: string, ConfType: type): auto =
  makeBannerAndConfig(
    helpBanner, ["Ethereum consensus spec v" & SPEC_VERSION], [], ConfType
  ).valueOr:
    try:
      stderr.write(error)
    except IOError:
      discard
    quit QuitFailure

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

proc sleepAsync*(t: TimeDiff): Future[void] {.
     async: (raises: [CancelledError], raw: true).} =
  sleepAsync(nanoseconds(
    if t.nanoseconds < 0: 0'i64 else: t.nanoseconds))

proc init*(T: type RestServerRef,
           ip: IpAddress,
           port: Port,
           allowedOrigin: Option[string],
           validateFn: PatternCallback,
           ident: string,
           config: auto): T =
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
                              serverIdent = ident,
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
    config: auto,
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

    when compiles(config.restPort):
      if existingRestServer != nil and
         config.restAddress == config.keymanagerAddress and
        config.restPort == config.keymanagerPort:
        existingRestServer
      else:
        RestServerRef.init(config.keymanagerAddress, config.keymanagerPort,
                           config.keymanagerAllowedOrigin,
                           validateKeymanagerApiQueries,
                           nimbusAgentStr,
                           config)
    else:
      RestServerRef.init(config.keymanagerAddress, config.keymanagerPort,
                         config.keymanagerAllowedOrigin,
                         validateKeymanagerApiQueries,
                         nimbusAgentStr,
                         config)
  else:
    nil

  KeymanagerInitResult(server: keymanagerServer, token: token)

proc initMetricsServer*(
    config: auto
): Future[Result[Opt[MetricsHttpServerRef], string]] {.
  async: (raises: [CancelledError]).} =
  if config.metricsEnabled:
    let
      metricsAddress = config.metricsAddress
      metricsPort = config.metricsPort
      url = "http://" & $metricsAddress & ":" & $metricsPort & "/metrics"

    info "Starting metrics HTTP server", url = url

    let server = MetricsHttpServerRef.new($metricsAddress, metricsPort).valueOr:
      fatal "Could not start metrics HTTP server",
            url = url, reason = error
      return err($error)

    try:
      await server.start()
    except MetricsError as exc:
      fatal "Could not start metrics HTTP server",
            url = url, reason = exc.msg
      return err(exc.msg)

    ok(Opt.some(server))
  else:
    ok(Opt.none(MetricsHttpServerRef))

proc stopMetricsServer*(v: Opt[MetricsHttpServerRef]) {.
     async: (raises: []).} =
  if v.isSome():
    info "Shutting down metrics HTTP server"
    await v.get().close()

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

proc quitSlashing*() =
  fatal "A known validator is slashed"

  const QuitSlashing = 198
  quit QuitSlashing

proc defaultDataDir*(namespace, network: string): string =
  ## Return the location to use by default for the given network - since
  ## each network has its own blocks and configuration, separate the data
  ## directories by chain to keep things simple.
  ##
  ## Namespace is for separating applications by namespace, ie when they don't
  ## support sharing data directory - in particular, the validator client,
  ## signing node and beacon node must use separate folders or they risk loading
  ## the same keys!
  ##
  ## In theory, things like private keys could be shared between testnets and
  ## mainnet, but this amounts to reusing the same keys for both environments
  ## which seems dubious at best, security-wise.

  let
    base =
      when defined(windows):
        # Avoid roaming profile since DB is large
        os.getEnv("LOCALAPPDATA", os.getEnv("APPDATA"))
      elif defined(macos) or defined(macosx):
        # Everything goes in here on mac
        os.getHomeDir() / "Library/Application Support"
      else:
        # https://specifications.freedesktop.org/basedir-spec/0.8/#variables
        os.getEnv("XDG_STATE_HOME", os.getEnv("HOME") / ".local/state")

    nimbus = when defined(linux): "nimbus" else: "Nimbus"

  var dir = base / nimbus

  if namespace.len > 0:
    dir = dir / namespace

  if network.len > 0:
    dir = dir / network

  dir
