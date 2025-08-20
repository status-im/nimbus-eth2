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
  var signalTarget = pthread_self()

  proc ignoreStopSignalsInThread*(_: type ProcessState) =
    # Block all signals in this thread, so we don't interfere with regular signal
    # handling elsewhere.
    var signalMask, oldSignalMask: Sigset

    if sigemptyset(signalMask) != 0:
      fatal "Error creating signal mask", err = osErrorMsg(osLastError())
      quit(QuitFailure)

    if sigaddset(signalMask, posix.SIGINT) != 0:
      fatal "Error updating signal mask", err = osErrorMsg(osLastError())
      quit(QuitFailure)
    if sigaddset(signalMask, posix.SIGTERM) != 0:
      fatal "Error updating signal mask", err = osErrorMsg(osLastError())
      quit(QuitFailure)

    if pthread_sigmask(SIG_BLOCK, signalMask, oldSignalMask) != 0:
      fatal "Error setting signal mask", err = osErrorMsg(osLastError())
      quit(QuitFailure)

    debug "Ignoring signals in thread", chroniclesThreadIds = true

  proc raiseStopSignal() =
    # Main thread that is monitoring the signals...
    discard pthread_kill(signalTarget, posix.SIGTERM)

else:
  proc ignoreStopSignalsInThread*(_: type ProcessState) =
    discard

  proc raiseStopSignal() =
    discard c_raise(ansi_c.SIGINT)

proc scheduleStop*(_: type ProcessState, source: cstring) =
  debug "Scheduling shutdown", source
  var nilptr: pointer
  discard shutdownSource.compareExchange(nilptr, source)
  raiseStopSignal()

proc notifyRunning*(_: type ProcessState) =
  processState.store(ProcessState.Running, moRelaxed)

proc setupStopHandlers*(_: type ProcessState) =
  ## Install signal handlers for SIGINT/SIGTERM such that the application
  ## updates `processState` on CTRL-C and similar, allowing it to gracefully
  ## shut down.
  ##
  ## The CTRL-C handling provided by `signal` does not wake the async polling
  ## loop and can therefore get stuck if no events are happening - see
  ## `waitStopSignals` for a version that works with the chronos poll loop.
  ##
  ## This function should be called early on from the main thread to avoid the
  ## default Nim signal handlers from being used as these will crash or close
  ## the application.
  ##
  ## Non-main threads should instead call `ignoreStopSignalsInThread`

  proc controlCHandler(a: cint) {.noconv.} =
    # Cannot log in here because that would imply memory allocations and system
    # calls
    let sourceName =
      if a == ansi_c.SIGINT:
        cstring("SIGINT")
      else:
        cstring("SIGTERM")

    var nilptr: pointer
    discard shutdownSource.compareExchange(nilptr, sourceName)
    # Should also provide synchronization for the shutdownSource write..
    processState.store(Stopping)

  # Avoid using `setControlCHook` since it has an exception effect
  c_signal(ansi_c.SIGINT, controlCHandler)

  # equivalent SIGTERM handler
  when declared(ansi_c.SIGTERM):
    c_signal(ansi_c.SIGTERM, controlCHandler)

proc waitStopSignals*(_: type ProcessState) {.async: (raises: [CancelledError]).} =
  ## Monitor stop signals via chronos' event loop, masking other handlers.
  ##
  ## This approach ensures that the event loop wakes up on signal delivery
  ## unlike `setupStopHandlers` which merely sets a flag that must be polled.
  let
    sigint = waitSignal(chronos.SIGINT)
    sigterm =
      when defined(windows):
        default(array[0, FutureBase])
      else:
        [waitSignal(chronos.SIGTERM)]

  debug "Waiting for signal", chroniclesThreadIds = true

  try:
    discard await race(sigint, sigterm)
    processState.store(ProcessState.Stopping, moRelaxed)
  finally:
    # Might be finished already, which is fine..
    await noCancel sigint.cancelAndWait()
    for f in sigterm:
      await noCancel f.cancelAndWait()

proc stopping*(_: type ProcessState): bool =
  processState.load(moRelaxed) == ProcessState.Stopping

proc pollUntilStopped*(_: type ProcessState) =
  while processState.load(moRelaxed) != ProcessState.Stopping:
    poll()

  var source = cast[cstring](shutdownSource.load())
  if source == nil:
    source = "Unknown"
  notice "Shutting down", chroniclesThreadIds = true, source

when isMainModule: # Test case
  import os

  proc threadWork() {.async.} =
    var todo = 2
    while todo > 0:
      echo "Terminating in ", todo

      await sleepAsync(1.seconds)
      todo -= 1

    ProcessState.scheduleStop("thread")

    echo "Waiting for the end... "
    await sleepAsync(10.seconds)

    raiseAssert "Should not reach here, ie stopping the thread should not take 10s"

  proc worker(p: ThreadSignalPtr) {.thread.} =
    ProcessState.ignoreStopSignalsInThread()
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

    let stop = ProcessState.waitStopSignals()

    ProcessState.pollUntilStopped()
    waitFor stopper.fire()

    waitFor stop.cancelAndWait()

    workerThread.joinThread()

    ProcessState.notifyRunning()

    # The async waiting has finished - let's try the sync waiting
    ProcessState.scheduleStop("done")

    # poll for 10s, this should be enough
    for i in 0 ..< 100:
      if ProcessState.stopping():
        break
      os.sleep(100)

    doAssert ProcessState.stopping()

  main()
