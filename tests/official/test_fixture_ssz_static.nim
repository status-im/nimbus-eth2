# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, strutils, strformat, tables, unittest, sequtils, typetraits,
  # Status libs
  stew/[byteutils, bitseqs], nimcrypto/hash,
  serialization/testing/tracing,
  json_serialization, json_serialization/lexer,
  # Beacon chain internals
  ../../beacon_chain/ssz,
  ../../beacon_chain/spec/[datatypes, validator, digest, crypto],
  # Test utilities
  ../testutil,
  ./fixtures_utils_v0_8_1

const
  failFast = defined(debug) and false
  traceOnFailure = defined(debug)

type
  SpecObject[T] = ref object of RootObj
    obj: ref T

  SszStaticTest* = object
    obj: RootRef
    objType, objJsonRepr: string
    expectedBytes: seq[byte]
    expectedRootHash, expectedSigHash: Eth2Digest
    hasSigHash: bool
    line: int

  ReaderProc = proc(r: var JsonReader): RootRef {.cdecl, gcsafe.}
  TestingProc = proc(file: string, test: SszStaticTest) {.cdecl, gcsafe.}

  SpecTypeVtable = object
    reader: ReaderProc
    tester: TestingProc

let testsDir = JsonTestsDir / "ssz_static" / "core"
let minDevTestFile = getTempDir() / "minimal_ssz_test.json"

var specTypesRTTI = initTable[string, SpecTypeVtable]()

proc readerImpl[T](r: var JsonReader): RootRef {.cdecl, gcsafe.} =
  var res = SpecObject[T](obj: new T)
  res.obj[] = r.readValue(T)
  RootRef(res)

# TODO:
# Fun fact: With mainnet settings, the BeaconState object
# is too large to safely exist as a stack variable. The
# `testerImpl` procedure below will trigger a segmentation
# fault on its very first line because of it.
#
# To work-around this issue, this file uses ref objects
# to store the loaded test cases, but we must compare them
# by value:
template valuesAreEqual[T](a, b: ref T): bool =
  a[] == b[]

template valuesAreEqual[T](a, b: T): bool =
  a == b

template `$`(x: ref auto): string =
  $(x[])

proc readSszValueRef*(input: openarray[byte], T: type): ref T =
  new result
  result[] = readSszValue(input, T)

proc testerImpl[T](path: string, sszTest: SszStaticTest) {.cdecl, gcsafe.} =
  doAssert sszTest.obj != nil
  var obj = SpecObject[T](sszTest.obj)

  test &"test case on line {sszTest.line}":
    template execTest(testOpName, testOp, expectedRes) =
      let ourRes = testOp
      let success = valuesAreEqual(ourRes, expectedRes)
      if not success and traceOnFailure:
        {.gcsafe.}:
          echo "====== ", testOpName, " failed ", path, ":", sszTest.line
          echo " our result:"
          echo "  ", ourRes
          echo " expected result:"
          echo "  ", expectedRes
          when defined(serialization_tracing):
            tracingEnabled = true
            discard testOp
            tracingEnabled = false
          echo "======================================================"
          if failFast: quit 1

      # TODO BEWARE: Passing the boolean expression to `check` directly
      # will trigger a Nim compilation bomb. This is most likely caused
      # by a mis-behaving generics instantiations cache when a function
      # is explicitly instantiated to get its address.
      # There is a recursive instantiation loop of system's `$` operator.
      check success

    execTest "serialization",
              (let ourBytes = SSZ.encode(obj.obj[]); ourBytes),
              sszTest.expectedBytes

    execTest "root hash check",
              hash_tree_root(obj.obj[]),
              sszTest.expectedRootHash

    when hasSigningRoot(T):
      doAssert sszTest.hasSigHash
      execTest "sig hash check",
               signingRoot(obj.obj[]),
               sszTest.expectedSigHash

    execTest "roundtrip",
           readSszValueRef(sszTest.expectedBytes, T),
           obj.obj

template addSpecTypeRTTI(T: type) =
  var reader = readerImpl[T]
  var tester = testerImpl[T]
  specTypesRTTI.add(T.name, SpecTypeVtable(reader: reader,
                                           tester: tester))
foreachSpecType(addSpecTypeRTTI)

proc runTest(path: string, test: SszStaticTest) =
  if test.objType != "Unsupported":
    specTypesRTTI[test.objType].tester(path, test)

proc advanceToClosingBrace(lexer: var JsonLexer, openedBraces = 1) =
  var closedBraces = 0
  while closedBraces < openedBraces:
    while lexer.tok notin {tkCurlyLe, tkCurlyRi}:
      lexer.next
    if lexer.tok == tkCurlyLe:
      dec closedBraces
    else:
      inc closedBraces
    lexer.next

proc readValue*(r: var JsonReader, result: var SszStaticTest) {.gcsafe.} =
  r.skipToken tkCurlyLe

  if r.lexer.tok != tkString:
    r.raiseUnexpectedToken(etString)

  var reader: ReaderProc
  let key = r.lexer.strVal
  {.gcsafe.}:
    if not specTypesRTTI.hasKey(key):
      result.objType = "Unsupported"
      r.lexer.advanceToClosingBrace
      return

    result.objType = key
    result.line = r.lexer.line
    reader = specTypesRTTI[key].reader

  r.lexer.next
  r.skipToken tkColon
  r.skipToken tkCurlyLe

  while r.lexer.tok == tkString:
    # TODO: I was hit by a very nasty Nim bug here.
    # If you use `let` on the next line, the variable will be
    # aliased to `r.lexer.strVar` instead of being copied.
    # This will create problems, because the value is modified
    # on the next line.
    var field = r.lexer.strVal
    r.lexer.next
    r.skipToken tkColon

    case field
    of "value":
      result.obj = reader(r)
    of "serialized":
      result.expectedBytes = hexToSeqByte r.readValue(string)
    of "root":
      result.expectedRootHash = Eth2Digest.fromHex r.readValue(string)
    of "signing_root":
      result.expectedSigHash = Eth2Digest.fromHex r.readValue(string)
      result.hasSigHash = true
    else:
      r.raiseUnexpectedField(field, type(result).name)

    if r.lexer.tok == tkComma:
      r.lexer.next()
    else:
      break

  r.skipToken tkCurlyRi
  r.skipToken tkCurlyRi

  when failFast:
    # This will produce faster failures in debug builds
    {.gcsafe.}: runTest result

proc executeSuite(path: string) =
  let sszSuite = path.parseTests SszStaticTest
  suite &"{path}: {sszSuite.title}":
    for sszTest in sszSuite.test_cases:
      runTest path, sszTest

if fileExists(minDevTestFile):
  executeSuite minDevTestFile

for kind, path in walkDir(testsDir):
  if kind notin {pcFile, pcLinkToFile}: continue
  if const_preset in path:
    executeSuite path
