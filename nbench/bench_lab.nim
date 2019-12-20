# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard lib
  macros, std/[monotimes, times],
  # Internal
  platforms/x86

# Bench laboratory
# --------------------------------------------------
#
# This file defines support data structures to enable profiling.

# Utils
# --------------------------------------------------
const someGcc = defined(gcc) or defined(llvm_gcc) or defined(clang) or defined(icc)
const hasThreadSupport = defined(threads)

proc atomicInc*(memLoc: var int64, x = 1'i64): int64 =
  when someGcc and hasThreadSupport:
    result = atomicAddFetch(memLoc.addr, x, ATOMIC_RELAXED)
  elif defined(vcc) and hasThreadSupport:
    result = addAndFetch(memLoc.addr, x)
    result += x
  else:
    memloc += x
    result = memLoc

# Types
# --------------------------------------------------

type
  Metadata* = object
    procName*: string
    module: string
    package: string
    tag: string # Can be change to multi-tags later
    # TODO - replace by eth-metrics once we figure out a CSV/JSON/Console backend
    numCalls*: int64
    cumulatedTimeNs*: int64 # in nanoseconds
    cumulatedCycles*: int64

var ctBenchMetrics*{.compileTime.}: seq[Metadata]
  ## Metrics are collected here, this is just a temporary holder of compileTime values
  ## Unfortunately the "seq" is emptied when passing the compileTime/runtime boundaries
  ## due to Nim bugs

var BenchMetrics*: seq[Metadata]
  ## We can't directly use it at compileTime because it doesn't exist.
  ## We need `BenchMetrics = static(ctBenchMetrics)`
  ## To transfer the compileTime content to runtime at an opportune time.

template ntag(tagname: string){.pragma.}
  ## This will allow tagging proc in the future with
  ## "crypto", "ssz", "block_transition", "epoch_transition" ...

# Symbols
# --------------------------------------------------

template fnEntry(name: string, id: int, startTime, startCycle: untyped): untyped =
  ## Bench tracing to insert on function entry
  {.noSideEffect.}:
    discard BenchMetrics[id].numCalls.atomicInc()
    let startTime = getMonoTime()
    let startCycle = getTicks()

const nbench_trace {.booldefine.} = off # For manual "debug-echo"-style timing.
when nbench_trace:
  # strformat doesn't work in templates.
  from strutils import alignLeft, formatFloat

template fnExit(name: string, id: int, startTime, startCycle: untyped): untyped =
  ## Bench tracing to insert before each function exit
  {.noSideEffect.}:
    let stopCycle = getTicks()
    let stopTime = getMonoTime()
    let elapsedCycles = stopCycle - startCycle
    let elapsedTime = inNanoseconds(stopTime - startTime)

    discard BenchMetrics[id].cumulatedTimeNs.atomicInc(elapsedTime)
    discard BenchMetrics[id].cumulatedCycles.atomicInc(elapsedCycles)

    when nbench_trace:
      # Advice: Use "when name == relevantProc" to isolate specific procedures.
      # strformat doesn't work in templates.
      echo static(alignLeft(name, 50)),
           "Time (ms): ", alignLeft(formatFloat(elapsedTime.float64 * 1e-6, precision=3), 10),
           "Cycles (billions): ", formatFloat(elapsedCycles.float64 * 1e-9, precision=3)

macro nbenchAnnotate(procAst: untyped): untyped =
  procAst.expectKind({nnkProcDef, nnkFuncDef})

  let id = ctBenchMetrics.len
  let name = procAst[0]
  # TODO, get the module and the package the proc is coming from
  #       and the tag "crypto", "ssz", "block_transition", "epoch_transition" ...

  ctBenchMetrics.add Metadata(procName: $name, numCalls: 0, cumulatedTimeNs: 0, cumulatedCycles: 0)
  var newBody = newStmtList()
  let startTime = genSym(nskLet, "nbench_" & $name & "_startTime_")
  let startCycle = genSym(nskLet, "nbench_" & $name & "_startCycles_")
  newBody.add getAst(fnEntry($name, id, startTime, startCycle))
  newbody.add nnkDefer.newTree(getAst(fnExit($name, id, startTime, startCycle)))
  newBody.add procAst.body

  procAst.body = newBody
  result = procAst

template nbench*(procBody: untyped): untyped =
  when defined(nbench):
    nbenchAnnotate(procBody)
  else:
    procBody

# Sanity checks
# ---------------------------------------------------

when isMainModule:

  expandMacros:
    proc foo(x: int): int{.nbench.} =
      echo "Hey hey hey"
      result = x

  BenchMetrics = static(ctBenchMetrics)

  echo BenchMetrics
  discard foo(10)
  echo BenchMetrics
  doAssert BenchMetrics[0].numCalls == 1
