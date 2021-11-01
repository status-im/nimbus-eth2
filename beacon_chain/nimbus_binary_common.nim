# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# Common routines for a BeaconNode and a ValidatorClient

import
  # Standard library
  std/[os, tables, strutils, terminal, typetraits],

  # Nimble packages
  chronos, confutils/defs,
  chronicles, chronicles/helpers as chroniclesHelpers, chronicles/topics_registry,
  stew/io2,

  # Local modules
  ./spec/[helpers],
  ./spec/datatypes/base,
  "."/[beacon_clock, conf, filepath, beacon_node_status]

when defined(posix):
  import termios

export beacon_node_status

type
  SlotStartProc*[T] = proc(node: T, wallTime: BeaconTime,
                           lastSlot: Slot): Future[void] {.gcsafe,
  raises: [Defect].}

# silly chronicles, colors is a compile-time property
proc stripAnsi(v: string): string =
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

proc updateLogLevel*(logLevel: string) {.raises: [Defect, ValueError].} =
  # Updates log levels (without clearing old ones)
  let directives = logLevel.split(";")
  try:
    setLogLevel(parseEnum[LogLevel](directives[0]))
  except ValueError:
    raise (ref ValueError)(msg: "Please specify one of TRACE, DEBUG, INFO, NOTICE, WARN, ERROR or FATAL")

  if directives.len > 1:
    for topicName, settings in parseTopicDirectives(directives[1..^1]):
      if not setTopicState(topicName, settings.state, settings.logLevel):
        warn "Unrecognized logging topic", topic = topicName

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

    let tmp =
      if stdoutKind == StdoutLogKind.Auto:
        if logFile.isSome():
          # No stdout logging by default, when file logging is enabled
          StdoutLogKind.None
        elif isatty(stdout):
          # On a TTY, let's be fancy
          StdoutLogKind.Colors
        else:
          # When there's no TTY, we output no colors because this matches what
          # released binaries were doing before auto-detection was around and
          # looks decent in systemd-captured journals.
          StdoutLogKind.NoColors
      else:
        stdoutKind

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
  let config = ConfType.load(
    version = version,
    copyrightBanner = clientId) # but a short version string makes more sense...
  {.pop.}
  config

# TODO not sure if this belongs here but it doesn't belong in `beacon_clock.nim` either
proc sleepToSlotOffset*(clock: BeaconClock, extra: chronos.Duration,
                        slot: Slot, msg: static string): Future[bool] {.async.} =
  let
    fromNow = clock.fromNow(slot.toBeaconTime(extra))

  if fromNow.inFuture:
    trace msg,
      slot = shortLog(slot),
      fromNow = shortLog(fromNow.offset)

    await sleepAsync(fromNow.offset)
    return true
  return false

proc checkIfShouldStopAtEpoch*(scheduledSlot: Slot, stopAtEpoch: uint64) =
  # Offset backwards slightly to allow this epoch's finalization check to occur
  if scheduledSlot > 3 and stopAtEpoch > 0'u64 and
      (scheduledSlot - 3).compute_epoch_at_slot() >= stopAtEpoch:
    info "Stopping at pre-chosen epoch",
      chosenEpoch = stopAtEpoch,
      epoch = scheduledSlot.compute_epoch_at_slot(),
      slot = scheduledSlot

    # Brute-force, but ensure it's reliable enough to run in CI.
    quit(0)

proc resetStdin*() =
  when defined(posix):
    # restore echoing, in case it was disabled by a password prompt
    let fd = stdin.getFileHandle()
    var attrs: Termios
    discard fd.tcGetAttr(attrs.addr)
    attrs.c_lflag = attrs.c_lflag or Cflag(ECHO)
    discard fd.tcSetAttr(TCSANOW, attrs.addr)

proc runSlotLoop*[T](node: T, startTime: BeaconTime,
                     slotProc: SlotStartProc[T]) {.async.} =
  var
    curSlot = startTime.slotOrZero()
    nextSlot = curSlot + 1 # No earlier than GENESIS_SLOT + 1
    timeToNextSlot = nextSlot.toBeaconTime() - startTime

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
      timeToNextSlot = nextSlot.toBeaconTime() - wallTime
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
          delay = shortLog(wallTime - nextSlot.toBeaconTime()),
          curSlot = shortLog(curSlot),
          nextSlot = shortLog(curSlot)

    await slotProc(node, wallTime, curSlot)

    curSlot = wallSlot
    nextSlot = wallSlot + 1
    timeToNextSlot = saturate(node.beaconClock.fromNow(nextSlot))
