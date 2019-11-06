# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest, strutils, streams, strformat, strscans,
  macros,
  # Status libraries
  stint, stew/bitseqs,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, digest],
  ../../beacon_chain/ssz,
  # Test utilities
  ../testutil

# Parsing definitions
# ------------------------------------------------------------------------

const
  FixturesDir = currentSourcePath.rsplit(DirSep, 1)[0] / "fixtures"
  SSZDir = FixturesDir/"tests-v0.9.0"/"general"/"phase0"/"ssz_generic"

type
  SSZHashTreeRoot = object
    # The test files have the values at the "root"
    # so we **must** use "root" as a field name
    root: string
    # Containers have a root (thankfully) and signing_root field
    signing_root: string

# Make signing root optional
setDefaultValue(SSZHashTreeRoot, signing_root, "")

# Type specific checks
# ------------------------------------------------------------------------

proc checkBasic(T:typedesc, dir: string, expectedHash: SSZHashTreeRoot) =
  let deserialized = SSZ.loadFile(dir/"serialized.ssz", T)
  check:
    expectedHash.root == "0x" & toLowerASCII($deserialized.hashTreeRoot())
  # TODO check the value

macro testVector(typeIdent: string, size: int): untyped =
  # find the compile-time type to test
  # against the runtime combination (cartesian product) of
  #
  # types: bool, uint8, uint16, uint32, uint64, uint128, uint256
  # sizes: 1, 2, 3, 4, 5, 8, 16, 31, 512, 513
  #
  # We allocate in a ref array to not run out of stack space
  let types = ["bool", "uint8", "uint16", "uint32", "uint64"] # "uint128", "uint256"]
  let sizes = [1, 2, 3, 4, 5, 8, 16, 31, 512, 513]

  var dispatcher = nnkIfStmt.newTree()
  for t in types:
    # if typeIdent == t // elif typeIdent == t
    var sizeDispatch = nnkIfStmt.newTree()
    for s in sizes:
      # if size == s // elif size == s
      let T = nnkBracketExpr.newTree(
        ident"array", newLit(s), ident(t)
      )
      var testStmt = quote do:
        # Need heap alloc
        var deserialized: ref `T`
        new deserialized
        deserialized[] = SSZ.loadFile(dir/"serialized.ssz", `T`)
        check:
          expectedHash.root == "0x" & toLowerASCII($deserialized.hashTreeRoot())
          # TODO check the value
      sizeDispatch.add nnkElifBranch.newTree(
        newCall(ident"==", size, newLit(s)),
        testStmt
      )
    sizeDispatch.add nnkElse.newTree quote do:
      raise newException(ValueError,
        "Unsupported **size** in type/size combination: array[" &
        $size & "," & typeIdent & ']')
    dispatcher.add nnkElifBranch.newTree(
      newCall(ident"==", typeIdent, newLit(t)),
      sizeDispatch
    )
  dispatcher.add nnkElse.newTree quote do:
    # TODO: support uint128 and uint256
    if `typeIdent` != "uint128" and `typeIdent` != "uint256":
      raise newException(ValueError,
        "Unsupported **type** in type/size combination: array[" &
        $`size` & ", " & `typeIdent` & ']')

  result = dispatcher
  # echo result.toStrLit() # view the generated code

proc checkVector(sszSubType, dir: string, expectedHash: SSZHashTreeRoot) =
  var typeIdent: string
  var size: int
  let wasMatched = scanf(sszSubType, "vec_$+_$i", typeIdent, size)
  if typeIdent == "uint128" or typeIdent == "uint256":
    echo &"       (SSZ) Vector[{typeIdent:7}, {size:3}] - skipped"
  else:
    echo &"       (SSZ) Vector[{typeIdent:7}, {size:3}]"
  testVector(typeIdent, size)

type BitContainer[N: static int] = BitList[N] or BitArray[N]

proc testBitContainer(T: typedesc[BitContainer], dir: string, expectedHash: SSZHashTreeRoot) =
  let deserialized = SSZ.loadFile(dir/"serialized.ssz", T)
  check:
    expectedHash.root == "0x" & toLowerASCII($deserialized.hashTreeRoot())
  # TODO check the value

proc checkBitVector(sszSubType, dir: string, expectedHash: SSZHashTreeRoot) =
  var size: int
  let wasMatched = scanf(sszSubType, "bitvec_$i", size)
  case size
  of 1: testBitContainer(BitArray[1], dir, expectedHash)
  of 2: testBitContainer(BitArray[2], dir, expectedHash)
  of 3: testBitContainer(BitArray[3], dir, expectedHash)
  of 4: testBitContainer(BitArray[4], dir, expectedHash)
  of 5: testBitContainer(BitArray[5], dir, expectedHash)
  of 8: testBitContainer(BitArray[8], dir, expectedHash)
  of 16: testBitContainer(BitArray[16], dir, expectedHash)
  of 31: testBitContainer(BitArray[31], dir, expectedHash)
  of 512: testBitContainer(BitArray[512], dir, expectedHash)
  of 513: testBitContainer(BitArray[513], dir, expectedHash)
  else:
    raise newException(ValueError, "Unsupported BitVector of size " & $size)

# TODO: serialization of "type BitList[maxLen] = distinct BitSeq is not supported"
#       https://github.com/status-im/nim-beacon-chain/issues/518
# proc checkBitList(sszSubType, dir: string, expectedHash: SSZHashTreeRoot) =
#   var maxLen: int
#   let wasMatched = scanf(sszSubType, "bitlist_$i", maxLen)
#   case maxLen
#   of 1: testBitContainer(BitList[1], dir, expectedHash)
#   of 2: testBitContainer(BitList[2], dir, expectedHash)
#   of 3: testBitContainer(BitList[3], dir, expectedHash)
#   of 4: testBitContainer(BitList[4], dir, expectedHash)
#   of 5: testBitContainer(BitList[5], dir, expectedHash)
#   of 8: testBitContainer(BitList[8], dir, expectedHash)
#   of 16: testBitContainer(BitList[16], dir, expectedHash)
#   of 31: testBitContainer(BitList[31], dir, expectedHash)
#   of 512: testBitContainer(BitList[512], dir, expectedHash)
#   of 513: testBitContainer(BitList[513], dir, expectedHash)
#   else:
#     raise newException(ValueError, "Unsupported Bitlist of max length " & $maxLen)

# Test dispatch for valid inputs
# ------------------------------------------------------------------------

proc sszCheck(sszType, sszSubType: string) =
  let dir = SSZDir/sszType/"valid"/sszSubType

  # Hash tree root
  var expectedHash: SSZHashTreeRoot
  var s = openFileStream(dir/"meta.yaml")
  yaml.load(s, expectedHash)
  s.close()

  # Deserialization and checks
  case sszType
  of "boolean": checkBasic(bool, dir, expectedHash)
  of "uints":
    var bitsize: int
    let wasMatched = scanf(sszSubType, "uint_$i", bitsize)
    assert wasMatched
    case bitsize
    of 8:  checkBasic(uint8, dir, expectedHash)
    of 16: checkBasic(uint16, dir, expectedHash)
    of 32: checkBasic(uint32, dir, expectedHash)
    of 64: checkBasic(uint64, dir, expectedHash)
    of 128: discard # checkBasic(Stuint[128], dir, expectedHash) # TODO
    of 256: discard # checkBasic(Stuint[256], dir, expectedHash)
    else:
      raise newException(ValueError, "unknown uint in test: " & sszSubType)
  of "basic_vector": checkVector(sszSubType, dir, expectedHash)
  of "bit_vector": checkBitVector(sszSubType, dir, expectedHash)
  # of "bitlist": checkBitList(sszSubType, dir, expectedHash)
  else:
    discard # TODO

# Test dispatch for invalid inputs
# ------------------------------------------------------------------------

# TODO

# Test runner
# ------------------------------------------------------------------------

proc runSSZtests() =
  for pathKind, sszType in walkDir(SSZDir, relative = true):
    assert pathKind == pcDir
    test &"Testing {sszType:12} inputs - valid":
      let path = SSZDir/sszType/"valid"
      for pathKind, sszSubType in walkDir(path, relative = true):
        assert pathKind == pcDir
        sszCheck(sszType, sszSubType)

  # TODO: nim-serialization forces us to use exceptions as control flow
  #       as we always have to check user supplied inputs
  # Skipped
  # test "Testing " & name & " inputs (" & $T & ") - invalid":
  #   const path = SSZDir/name/"invalid"

suite "Official - 0.9.0 SSZ generic types":
  runSSZtests()
