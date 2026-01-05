# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## Process state helper using a global variable to coordinate multithreaded
## shutdown in the presence of C signals.
##
## The high-level idea is the following:
##
## * OS signals are monitored using `signal` - signals may be either
##   process-directed or thread-directed, but all of them end up in the
##   same `signal` handler as long as they're not masked
## * When the main thread launches another thread, it passes a "stop event" to
##   the thread - this can be a chronos ThreadSignalPtr, a condvar/lock or any
##   other cross-thread "wake-up" mechanism that can tell the thread that it's
##   time to go
## * When a signal is activated, a global flag is set indicating that the
##   polling loop of the main thread should stop
## * The main thread wakes up any threads it started and notifies them of the
##   imminent shutdown then waits for them to terminate
##
## `chronos` has a `waitSignal` function that could be use to wake it when a
## signal arrives - at the time of writing, it only works in a single-threaded
## application when chronos is the only signal handler and requires using
## its own raising mechanism instead of the standard `raise`/`pthread_kill`
## functions which makes it difficult to use:
## https://github.com/status-im/nim-chronos/issues/581
##
## As such, polling `ProcessState.stopping` ends up being the more reliable
## cross-platform solution in spite of its downsides.

{.push raises: [].}

import std/atomics, results

export results

type ProcessState* {.pure.} = enum
  Starting
  Running
  Stopping

var processState: Atomic[ProcessState]
var shutdownSource: Atomic[pointer]

import system/ansi_c

proc scheduleStop*(_: type ProcessState, source: cstring) =
  ## Schedule that the process should stop in a thread-safe way. This function
  ## can be used from non-nim threads as well.
  ##
  # TODO in theory, we could use `raise`/`kill`/`etc` depending on the platform
  #      to set `processState` from within the signal handler - if we were
  #      a kqueue/epoll-based signal handler, this would be the way to go so
  #      as to provide a wakeup notification - there are platform-based
  #      differences to take into account however, ie on kqueue, only process-
  #      directed signals are woken up whereas on linux, the signal has to
  #      reach the correct thread that is doing the waiting which requires
  #      special care.
  var nilptr: pointer
  discard shutdownSource.compareExchange(nilptr, source, moRelaxed)
  processState.store(ProcessState.Stopping)

proc notifyRunning*(_: type ProcessState) =
  processState.store(ProcessState.Running, moRelaxed)

proc setupStopHandlers*(_: type ProcessState) =
  ## Install signal handlers for SIGINT/SIGTERM such that the application
  ## updates `processState` on CTRL-C and similar, allowing it to gracefully
  ## shut down by monitoring `ProcessState.stopping` at regular intervals.
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

proc running*(_: type ProcessState): bool =
  processState.load(moRelaxed) == ProcessState.Running

proc stopping*(_: type ProcessState): Opt[cstring] =
  if processState.load(moRelaxed) == ProcessState.Stopping:
    var source = cast[cstring](shutdownSource.load(moRelaxed))
    if source == nil:
      source = "Stopped"
    ok source
  else:
    Opt.none(cstring)

template stopIt*(_: type ProcessState, body: untyped): bool =
  let state = ProcessState.stopping()
  if state.isSome():
    let it {.inject.} = state.get()
    body
    true
  else:
    false

when isMainModule: # Test case
  import os, chronos, chronos/threadsync

  proc threadWork() {.async.} =
    var todo = 2
    while todo > 0:
      # A few seconds to test ctrl-c-by-hand
      echo "Terminating in ", todo

      await sleepAsync(1.seconds)
      todo -= 1

    echo "notification from thread"
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

    echo "main thread waiting"
    while ProcessState.stopping.isNone:
      os.sleep(100)

    echo "main thread firing stopper"

    # Notify the thread should stop itself as well using a ThreadSignalPtr
    # rather than an OS signal - this is more portable
    waitFor stopper.fire()

    workerThread.joinThread()

    echo "notification from main thread"
    # Now let's reset and try the sync API
    ProcessState.notifyRunning()
    ProcessState.scheduleStop("done")

    # poll for 10s, this should be enough even on platforms with async signal
    # delivery (like windows, presumably?)
    for i in 0 ..< 100:
      if ProcessState.stopping().isSome:
        break
      os.sleep(100)

    echo "done"

    doAssert ProcessState.stopping().isSome

  main()
