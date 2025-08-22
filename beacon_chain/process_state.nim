# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Process state helper using a global variable to coordinate multithreaded
## shutdown in the presence of C signals
##
## The high-level idea is the following:
##
## * The main thread monitors OS signals using either `signal` or `waitSignal`
## * All other threads block signal handling using `ignoreStopSignalsInThread`
## * When the main thread launches another thread, it passes a "stop event" to
##   the thread - this can be a chronos ThreadSignalPtr, a condvar/lock or any
##   other cross-thread "wake-up" mechanism that can tell the thread that it's
##   time to go
## * When a signal is activated, a global flag is set indicating that the
##   polling loop of the main thread should stop
## * The main thread wakes up any threads it started and notifies them of the
##   imminent shutdown then waits for them to terminate
##
## In this way, the main thread is notified that _some_ thread or the user wants
## the process to shut down. The main thread stops whatever it's doing and
## notifies all threads it started that shutdown is imminent and then proceeds
## with the shutdown.

{.push raises: [].}

import std/atomics, chronos, chronos/threadsync, chronicles

type ProcessState* {.pure.} = enum
  Starting
  Running
  Stopping

var processState: Atomic[ProcessState]
var shutdownSource: Atomic[pointer]

import system/ansi_c

when defined(posix):
  import posix
  proc ignoreStopSignalsInThread*(_: type ProcessState): bool =
    # Block stop signals in the calling thread - this can be used to avoid
    # having certain threads be interrupted by process-directed signals
    var signalMask, oldSignalMask: Sigset

    if sigemptyset(signalMask) != 0:
      return false

    if sigaddset(signalMask, posix.SIGINT) != 0:
      return false
    if sigaddset(signalMask, posix.SIGTERM) != 0:
      return false

    if pthread_sigmask(SIG_BLOCK, signalMask, oldSignalMask) != 0:
      return false

    true

  proc raiseStopSignal() =
    discard c_raise(posix.SIGTERM)

else:
  proc ignoreStopSignalsInThread*(_: type ProcessState): bool =
    true

  import chronos/osutils

  proc raiseStopSignal() =
    discard c_raise(ansi_c.SIGINT)
    # Chronos installs its own handlers that are incompatible with `raise` -
    # when waitSignal is running we must also notify chronos
    discard osutils.raiseSignal(chronos.SIGINT)

proc scheduleStop*(_: type ProcessState, source: cstring) =
  ## Schedule that the process should stop in a thread-safe way. This function
  ## can be used from non-nim threads as well.
  var nilptr: pointer
  discard shutdownSource.compareExchange(nilptr, source)

  c_printf("XXXXXX: schedule %d\n")

  raiseStopSignal()

proc notifyRunning*(_: type ProcessState) =
  processState.store(ProcessState.Running, moRelaxed)

proc setupStopHandlers*(_: type ProcessState) =
  ## Install signal handlers for SIGINT/SIGTERM such that the application
  ## updates `processState` on CTRL-C and similar, allowing it to gracefully
  ## shut down by monitoring `ProcessState.running` at regular intervals.
  ##
  ## `async` applications should prefer to use
  ## `await ProcessState.waitStopsignals()` since the CTRL-C handling provided
  ## by `signal` does not wake the async polling loop and can therefore get
  ## stuck if no events are happening.
  ##
  ## This function should be called early on from the main thread to avoid the
  ## default Nim signal handlers from being used as these will crash or close
  ## the application.

  proc controlCHandler(a: cint) {.noconv.} =
    # Cannot log in here because that would imply memory allocations and system
    # calls
    let sourceName =
      if a == ansi_c.SIGINT:
        cstring("SIGINT")
      else:
        cstring("SIGTERM")
    c_printf("XXXXXX: handler %d\n")

    var nilptr: pointer
    discard shutdownSource.compareExchange(nilptr, sourceName)
    # Should also provide synchronization for the shutdownSource write..
    processState.store(Stopping)

  # Nim sets signal handlers using `c_signal`, but unfortunately these are broken
  # since they perform memory allocations and call unsafe system functions:
  # https://github.com/nim-lang/Nim/blob/c6352ce0ab5fef061b43c8ca960ff7728541b30b/lib/system/excpt.nim#L622

  # Avoid using `setControlCHook` since it has an exception effect
  c_signal(ansi_c.SIGINT, controlCHandler)

  # equivalent SIGTERM handler - this is only set on posix systems since on
  # windows, SIGTERM is not generated - however, chronos may generate them so
  # below, in the chronos version, we do monitor it on all platforms.
  # https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/signal?view=msvc-170
  when defined(posix):
    c_signal(ansi_c.SIGTERM, controlCHandler)

proc waitStopSignals*(_: type ProcessState) {.async: (raises: [CancelledError]).} =
  ## Monitor stop signals via chronos' event loop, masking other handlers.
  ##
  ## This approach ensures that the event loop wakes up on signal delivery
  ## unlike `setupStopHandlers` which merely sets a flag that must be polled.
  ##
  ## Make sure to call `ignoreStopSignalsInThread`

  let
    sigint = waitSignal(chronos.SIGINT)
    sigterm = waitSignal(chronos.SIGTERM)

  debug "Waiting for signal", chroniclesThreadIds = true

  try:
    discard await race(sigint, sigterm)

    var source = cast[cstring](shutdownSource.load())
    if source == nil:
      source = "Unknown"

    notice "Shutting down", chroniclesThreadIds = true, source

    processState.store(ProcessState.Stopping, moRelaxed)
  finally:
    # Might be finished already, which is fine..
    await noCancel sigint.cancelAndWait()
    await noCancel sigterm.cancelAndWait()

proc running*(_: type ProcessState): bool =
  processState.load(moRelaxed) == ProcessState.Running

proc stopping*(_: type ProcessState): bool =
  processState.load(moRelaxed) == ProcessState.Stopping

when isMainModule: # Test case
  import os

  proc threadWork() {.async.} =
    var todo = 2
    while todo > 0:
      echo "Terminating in ", todo

      await sleepAsync(1.seconds)
      todo -= 1

    # Sends signal from non-main thread
    ProcessState.scheduleStop("thread")

    echo "Waiting for the end... "
    await sleepAsync(10.seconds)

    raiseAssert "Should not reach here, ie stopping the thread should not take 10s"

  proc worker(p: ThreadSignalPtr) {.thread.} =
    let
      stop = p.wait()
      work = threadWork()
    discard waitFor noCancel race(stop, work)

    waitFor noCancel stop.cancelAndWait()
    waitFor noCancel work.cancelAndWait()

  proc main() {.raises: [CatchableError].} =
    let stopper = ThreadSignalPtr.new().expect("working thread signal")

    var workerThread: Thread[ThreadSignalPtr]
    createThread(workerThread, worker, stopper)

    # Setup sync stop handlers - these are used whenever `waitSignal` is not
    # used - whenever a `waitSignals` future is active, these signals should be
    # masked - even if they are not masked, they are harmless in that they
    # set the same flag as `waitStopSignals` does.
    ProcessState.setupStopHandlers()

    # Wait for a stop signal - this can be either the user pressing ctrl-c or
    # an out-of-band notification via kill/windows service command / some rest
    # API etc
    waitFor ProcessState.waitStopSignals()

    # Notify the thread should stop itself as well using a ThreadSignalPtr
    # rather than an OS signal
    waitFor stopper.fire()

    workerThread.joinThread()

    # Now let's reset and try the sync API
    ProcessState.notifyRunning()
    ProcessState.scheduleStop("done")

    # poll for 10s, this should be enough even on platforms with async signal
    # delivery (like windows, presumably?)
    for i in 0 ..< 100:
      if ProcessState.stopping():
        break
      os.sleep(100)

    doAssert ProcessState.stopping()

  main()
