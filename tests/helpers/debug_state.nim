# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  macros,
  nimcrypto/utils,
  ../../beacon_chain/spec/[datatypes, crypto, digest]
  # digest is necessary for them to be printed as hex

# Define comparison of object variants for BLSValue
# https://github.com/nim-lang/Nim/issues/6676
# (fully generic available - see also https://github.com/status-im/nim-beacon-chain/commit/993789bad684721bd7c74ea14b35c2d24dbb6e51)
# ----------------------------------------------------------------

proc `==`*[T](a, b: BlsValue[T]): bool =
  ## We sometimes need to compare real BlsValue
  ## from parsed opaque blobs that are not really on the BLS curve
  ## and full of zeros
  if a.kind == Real:
    if b.kind == Real:
      a.blsvalue == b.blsValue
    else:
      $a.blsvalue == toHex(b.blob, true)
  else:
    if b.kind == Real:
      toHex(a.blob, true) == $b.blsValue
    else:
      a.blob == b.blob

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
      "\nDiff: " & `xStr` & " = " & $`xSubField` & "\n" &
      "and   " & `yStr` & " = " & $`ySubField` & "\n"
    )

proc compareContainerStmt(xSubField, ySubField: NimNode, stmts: var NimNode) =
  let xStr = $xSubField.toStrLit
  let yStr = $ySubField.toStrLit


  stmts.add quote do:
    doAssert(
      `xSubField`.len == `ySubField`.len,
        "\nDiff: " & `xStr` & ".len = " & $`xSubField`.len & "\n" &
        "and   " & `yStr` & ".len = " & $`ySubField`.len & "\n"
    )
    for idx in `xSubField`.low .. `xSubField`.high:
      doAssert(
        `xSubField`[idx] == `ySubField`[idx],
        "\nDiff: " & `xStr` & "[" & $idx & "] = " & $`xSubField`[idx] & "\n" &
        "and   " & `yStr` & "[" & $idx & "] = " & $`ySubField`[idx] & "\n"
      )

proc inspectType(tImpl, xSubField, ySubField: NimNode, stmts: var NimNode) =
  # echo "kind: " & $tImpl.kind
  # echo "  -- field: " & $xSubField.toStrLit
  case tImpl.kind
  of nnkObjectTy:
    # pass the records
    let records = tImpl[2]
    records.expectKind(nnkRecList)
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
    if tImpl.kind == nnkBracketExpr:
      doAssert tImpl[0].eqIdent"List" or tImpl[0].eqIdent"seq" or tImpl[0].eqIdent"array", "Error: unsupported generic type: " & $tImpl[0]
      compareContainerStmt(xSubField, ySubField, stmts)
    elif $tImpl in builtinTypes:
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

macro reportDiff*(x, y: typed{`var`|`let`|`const`}): untyped =
  doAssert sameType(x, y)
  result = newStmtList()

  let typeImpl = x.getTypeImpl
  inspectType(typeImpl, x, y, result)

  # echo result.toStrLit

# -----------------------------------------
