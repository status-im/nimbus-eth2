# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  macros,
  ../../beacon_chain/spec/[datatypes, crypto]

# Define comparison of object variants for BLSValue
# https://github.com/nim-lang/Nim/issues/6676
# ----------------------------------------------------------------

proc processNode(arg, a,b, result: NimNode) =
  case arg.kind
  of nnkIdentDefs:
    let field = arg[0]
    result.add quote do:
      if `a`.`field` != `b`.`field`:
        return false
  of nnkRecCase:
    let kindField = arg[0][0]
    processNode(arg[0], a,b, result)
    let caseStmt = nnkCaseStmt.newTree(newDotExpr(a, kindField))
    for i in 1 ..< arg.len:
      let inputBranch = arg[i]
      let outputBranch = newTree(inputBranch.kind)
      let body = newStmtList()
      if inputBranch.kind == nnkOfBranch:
        outputBranch.add inputBranch[0]
        processNode(inputBranch[1], a,b, body)
      else:
        inputBranch.expectKind nnkElse
        processNode(inputBranch[0], a,b, body)
      outputBranch.add body
      caseStmt.add outputBranch
    result.add caseStmt
  of nnkRecList:
    for child in arg:
      child.expectKind {nnkIdentDefs, nnkRecCase}
      processNode(child, a,b, result)
  else:
    arg.expectKind {nnkIdentDefs, nnkRecCase, nnkRecList}

macro myCompareImpl(a,b: typed): untyped =
  a.expectKind nnkSym
  b.expectKind nnkSym

  let typeImpl = a.getTypeImpl
  # assert typeImpl == b.getTypeImpl # buggy

  var checks = newSeq[NimNode]()

  # uncomment to debug
  # echo typeImpl.treeRepr

  result = newStmtList()
  processNode(typeImpl[2], a, b, result)

  result.add quote do:
    return true

  # uncomment to debug
  # echo result.repr

proc `==`[T](a,b: BlsValue[T]): bool =
  myCompareImpl(a,b)
# ---------------------------------------------------------------------

# This tool inspects and compare 2 instances of a type recursively
# highlighting the differences

const builtinTypes = [
  "int", "int8", "int16", "int32", "int64",
  "uint", "uint8", "uint16", "uint32", "uint64",
  "byte", "float32", "float64",
  # "array", "seq", # wrapped in nnkBracketExpr
  "char", "string"
]

proc compareStmt(xSubField, ySubField: NimNode, stmts: var NimNode) =
  let xStr = $xSubField.toStrLit
  let yStr = $ySubField.toStrLit

  stmts.add quote do:
    doAssert(
      `xSubField` == `ySubField`,
      "Diff: " & `xStr` & " = " & $`xSubField` & "\n" &
      "and   " & `yStr` & " = " & $`ySubField` & "\n"
    )

proc inspectType(tImpl, xSubField, ySubField: NimNode, stmts: var NimNode) =
  # echo "kind: " & $tImpl.kind
  # echo "  -- field: " & $xSubField.toStrLit
  case tImpl.kind
  of nnkObjectTy:
    # pass the records
    let records = tImpl[2]
    assert records.kind == nnkRecList
    for decl in records:
      inspectType(
        decl[1], # field type
        nnkDotExpr.newTree(xSubField, decl[0]), # Accessor
        nnkDotExpr.newTree(ySubField, decl[0]),
        stmts
      )
  of {nnkRefTy, nnkDistinctTy}:
    inspectType(tImpl[0], xSubField, ySubField, stmts)
  of {nnkSym, nnkBracketExpr}:
    if tImpl.kind == nnkBracketExpr or $tImpl in builtinTypes:
      compareStmt(xSubField, ySubField, stmts)
    elif $tImpl in ["ValidatorSig", "ValidatorPubKey"]:
      # Workaround BlsValue being a case object
      compareStmt(xSubField, ySubField, stmts)
    else:
      inspectType(tImpl.getTypeImpl(), xSubField, ySubField, stmts)
  else:
    error "Unsupported kind: " & $tImpl.kind &
      " for field \"" & $xSubField.toStrLit &
      "\" of type \"" & tImpl.repr

macro reportDiff(x, y: typed{`var`|`let`|`const`}): untyped =
  assert sameType(x, y)
  result = newStmtList()

  let typeImpl = x.getTypeImpl
  inspectType(typeImpl, x, y, result)

  # echo result.toStrLit

# -----------------------------------------
