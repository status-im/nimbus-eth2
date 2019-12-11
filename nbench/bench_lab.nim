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

proc insertedAtExits(ast: NimNode, statement: NimNode): NimNode =
  ## Scan an AST, copy it with ``statement`` inserted at each exit point
  ##
  ## For example
  ##
  ## ```
  ## proc allGreater(s: seq[int], x: int): bool =
  ##    for i in 0 ..< s.len:
  ##      if s[i] <= x:
  ##        return false
  ##    return true
  ## ```
  ##
  ## will be transformed into
  ##
  ## ```
  ## proc allGreater(s: seq[int], x: int): bool =
  ##    for i in 0 ..< s.len:
  ##      if s[i] <= x:
  ##        statement
  ##        return false
  ##    statement
  ##    return true
  ## ```
  ##
  ## This is used for benchmarking hooks and has the following limitations due
  ## to the simplicity of implementation:
  ##
  ## - It assumes that the return statement is costless.
  ##   I.e. "return digest(x)" will miss digest.
  ##   This can be later fixed by always assigning the return value to result
  ##   then insert the bench statement
  ##   then return.
  ##
  ## - It assumes that the last statement is costless
  ##   and proc ending by an expression are common in the codebase

  proc inspect(node: NimNode, expressionsMayReturn: bool): NimNode =
    ## Recursively inspect the the AST tree.
    ## A return statement can happen anywhere
    ## while an expression that is also a return value can only
    ## happen as the last child of the current node
    # TODO: Does that handle "finally"?
    case node.kind
    of nnkReturnStmt:
      # Add our statement and re-add the return statement
      result = newStmtList()
      result.add statement
      result.add node
    of nnkStmtList, nnkStmtListExpr, nnkBlockStmt, nnkBlockExpr, nnkWhileStmt,
      nnkForStmt, nnkTryStmt:
      # New nested scope
      # We need to go deeper
      result = node.kind.newTree()
      for i in 0 ..< node.len - 1:
        # Check only return statement, up to the second-to-last statement
        result.add inspect(node[i], expressionsMayReturn = false)
      if node.len >= 1:
        # Check if the very last statement is a return,
        # or an expression (implicit return)
        #    if we are in the last nested scope
        #    of the last ... of the last nested scope
        result.add inspect(node[^1], expressionsMayReturn)
    of nnkIfStmt, nnkIfExpr:
      # in a conditional scope all blocks returns or don't not just the last one.
      result = node.kind.newTree()
      for conditionalBranch in node:
        result.add inspect(conditionalBranch, expressionsMayReturn)
    of nnkCaseStmt:
      result = node.kind.newTree()
      # Skip the first block which is a comparison
      result.add node[0]
      for i in 1 ..< node.len:
        result.add inspect(node[i], expressionsMayReturn)
    of nnkElifBranch, nnkElifExpr:
      # Only the last node carries the potential return statement/expression
      result = node.kind.newTree()
      result.add node[0]
      result.add inspect(node[^1], expressionsMayReturn)
    of nnkElse, nnkElseExpr:
      result = node.kind.newTree()
      result.add inspect(node[0], expressionsMayReturn)
    of nnkOfBranch:
      result = node.kind.newTree()
      for i in 0 ..< node.len - 1:
        result.add node[i]
      result.add inspect(node[^1], expressionsMayReturn)
    else:
      # We have an ident, a function call, an assignment,
      # for now we only insert our statement just before which means
      # if it was an expensive function call bench will be flawed - TODO
      if expressionsMayReturn:
        result = newStmtList()
        if node.kind == nnkAsgn and node[0].eqIdent"result":
          # At least catch the common case when result assignment is last
          result.add node
          result.add statement
        else:
          result.add statement
          result.add node
      else:
        # Not at the last statement of the scope so it can't
        # be an expression that returns
        return node

  ast.expectKind(nnkStmtList)
  result = ast.inspect(expressionsMayReturn = true)

template fnEntry(id: int, startTime, startCycle: untyped): untyped =
  ## Bench tracing to insert on function entry
  {.noSideEffect.}:
    discard BenchMetrics[id].numCalls.atomicInc()
    let startTime = getMonoTime()
    let startCycle = getTicks()

template fnExit(id: int, startTime, startCycle: untyped): untyped =
  ## Bench tracing to insert before each function exit
  {.noSideEffect.}:
    let stopCycle = getTicks()
    let stopTime = getMonoTime()

    discard BenchMetrics[id].cumulatedTimeNs.atomicInc(inNanoseconds(stopTime - startTime))
    discard BenchMetrics[id].cumulatedCycles.atomicInc(stopCycle - startCycle)

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
  newBody.add getAst(fnEntry(id, startTime, startCycle))
  newbody.add procAst.body.insertedAtExits(getAst(fnExit(id, startTime, startCycle)))

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

  macro echoAtExit(procAst: untyped): untyped =
    procAst.body = procAst.body.insertedAtExits(
      newCall(ident"echo", newLit"I'm an exit")
    )
    result = procAst
    echo result.toStrLit

  block:
    proc foo(x: int) {.echoAtExit.} =
      echo "Hello there"

    foo(10)

  block:
    proc foo(x: int): int {.echoAtExit.} =
      x

    discard foo(10)

  block:
    proc foo(x: int): int {.echoAtExit.} =
      if x > 5:
        x - 10
      else:
        x

    discard foo(10)

  block:
    proc foo(x: int): int {.echoAtExit.} =
      if x > 5:
        return x
      return 100

    discard foo(10)

  block:
    proc foo(x: int): int {.echoAtExit.} =
      if x > 5:
        return x
      result = 100

    discard foo(10)

  # --------------------------------------------

  expandMacros:
    proc foo(x: int): int{.nbench.} =
      echo "Hey hey hey"
      result = x

  BenchMetrics = static(ctBenchMetrics)

  echo BenchMetrics
  discard foo(10)
  echo BenchMetrics
  doAssert BenchMetrics[0].numCalls == 1
