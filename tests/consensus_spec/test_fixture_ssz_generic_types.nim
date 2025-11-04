# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  # Standard library
  std/[
    strutils, streams, strformat, strscans,
    macros, typetraits],
  # Status libraries
  faststreams, serialization/case_objects, snappy, stint, ../testutil,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../beacon_chain/spec/digest,
  ../../beacon_chain/spec/datatypes/base,
  # Test utilities
  ./fixtures_utils, ./os_ops

# Parsing definitions
# ------------------------------------------------------------------------

const
  SSZDir = SszTestsDir/"general"/"phase0"/"ssz_generic"

type
  SSZHashTreeRoot = object
    # The test files have the values at the "root"
    # so we **must** use "root" as a field name
    root: string
    # Containers have a root (thankfully) and signing_root field
    signing_root {.defaultVal: "".}: string

type
  # Heterogeneous containers
  SingleFieldTestStruct = object
    A: byte

  SmallTestStruct = object
    A, B: uint16

  FixedTestStruct = object
    A: uint8
    B: uint64
    C: uint32

  VarTestStruct = object
    A: uint16
    B: List[uint16, 1024]
    C: uint8

  ComplexTestStruct = object
    A: uint16
    B: List[uint16, 128]
    C: uint8
    D: List[byte, 256]
    E: VarTestStruct
    F: array[4, FixedTestStruct]
    G: array[2, VarTestStruct]

  HashArrayComplexTestStruct = object
    A: uint16
    B: List[uint16, 128]
    C: uint8
    D: List[byte, 256]
    E: VarTestStruct
    F: HashArray[4, FixedTestStruct]
    G: HashArray[2, VarTestStruct]

  ProgressiveTestStruct = object
    A: seq[byte]
    B: seq[uint64]
    C: seq[SmallTestStruct]
    D: seq[seq[VarTestStruct]]

  BitsStruct = object
    A: BitList[5]
    B: BitArray[2]
    C: BitArray[1]
    D: BitList[6]
    E: BitArray[8]

  ProgressiveBitsStruct = object
    A: BitArray[256]
    B: BitList[256]
    C: BitSeq
    D: BitArray[257]
    E: BitList[257]
    F: BitSeq
    G: BitArray[1280]
    H: BitList[1280]
    I: BitSeq
    J: BitArray[1281]
    K: BitList[1281]
    L: BitSeq

  ProgressiveSingleFieldContainerTestStruct
      {.sszActiveFields: [1].} = object
    A: byte

  ProgressiveSingleListContainerTestStruct
      {.sszActiveFields: [0, 0, 0, 0, 1].} = object
    C: BitSeq

  ProgressiveVarTestStruct
      {.sszActiveFields: [1, 0, 1, 0, 1].} = object
    A: byte
    B: List[uint16, 123]
    C: BitSeq

  ProgressiveComplexTestStruct
      {.sszActiveFields: [
        1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1
      ].} = object
    A: byte
    B: List[uint16, 123]
    C: BitSeq
    D: seq[uint64]
    E: seq[SmallTestStruct]
    F: seq[seq[VarTestStruct]]
    G: List[ProgressiveSingleFieldContainerTestStruct, 10]
    H: seq[ProgressiveVarTestStruct]

  SelectorA {.pure.} = enum
    a = 1
  CompatibleUnionA {.allowDiscriminatorsWithoutZero.} = object
    case selector: SelectorA
    of SelectorA.a: aData: ProgressiveSingleFieldContainerTestStruct

  SelectorBC {.pure.} = enum
    b = 2
    c = 3
  CompatibleUnionBC {.allowDiscriminatorsWithoutZero.} = object
    case selector: SelectorBC
    of SelectorBC.b: bData: ProgressiveSingleListContainerTestStruct
    of SelectorBC.c: cData: ProgressiveVarTestStruct

  SelectorABCA {.pure.} = enum
    a1 = 1
    b = 2
    c = 3
    a4 = 4
  CompatibleUnionABCA {.allowDiscriminatorsWithoutZero.} = object
    case selector: SelectorABCA
    of SelectorABCA.a1, SelectorABCA.a4:
      aData: ProgressiveSingleFieldContainerTestStruct
    of SelectorABCA.b: bData: ProgressiveSingleListContainerTestStruct
    of SelectorABCA.c: cData: ProgressiveVarTestStruct

# Type specific checks
# ------------------------------------------------------------------------

proc checkBasic(
    T: typedesc,
    dir: string,
    expectedHash: SSZHashTreeRoot
) {.raises: [IOError, SerializationError, UnconsumedInput].} =
  let fileContents = snappy.decode(readFileBytes(dir/"serialized.ssz_snappy"), MaxObjectSize)
  let deserialized = newClone(sszDecodeEntireInput(fileContents, T))

  let expectedHash = expectedHash.root
  let actualHash = "0x" & toLowerAscii($hash_tree_root(deserialized[]))

  check expectedHash == actualHash
  check sszSize(deserialized[]) == fileContents.len

  # TODO check the value

proc checkProgressiveList(
    sszSubType, dir: string, expectedHash: SSZHashTreeRoot
) {.raises: [
    IOError, SerializationError, TestSizeError, UnconsumedInput, ValueError].} =
  var typeIdent: string
  let wasMatched =
    try:
      scanf(sszSubType, "proglist_$+_", typeIdent)
    except ValueError:
      false  # Parsed `size` is out of range
  doAssert wasMatched

  case typeIdent
  of "bool":
    checkBasic(seq[bool], dir, expectedHash)
  of "uint8":
    checkBasic(seq[uint8], dir, expectedHash)
  of "uint16":
    checkBasic(seq[uint16], dir, expectedHash)
  of "uint32":
    checkBasic(seq[uint32], dir, expectedHash)
  of "uint64":
    checkBasic(seq[uint64], dir, expectedHash)
  of "uint128":
    checkBasic(seq[UInt128], dir, expectedHash)
  of "uint256":
    checkBasic(seq[UInt256], dir, expectedHash)
  else:
    raise newException(ValueError, "unknown ssz type in test: " & sszSubType)

macro testVector(typeIdent: string, size: int): untyped =
  # find the compile-time type to test
  # against the runtime combination (cartesian product) of
  #
  # types: bool, uint8, uint16, uint32, uint64, uint128, uint256
  # sizes: 1, 2, 3, 4, 5, 8, 16, 31, 512, 513
  #
  # We allocate in a ref array to not run out of stack space
  let types = ["bool", "uint8", "uint16", "uint32", "uint64", "uint128", "uint256"]
  let sizes = [1, 2, 3, 4, 5, 8, 16, 31, 512, 513]

  let dispatcher = nnkIfStmt.newTree()
  for t in types:
    # if typeIdent == t // elif typeIdent == t
    let sizeDispatch = nnkIfStmt.newTree()
    for s in sizes:
      # if size == s // elif size == s
      let T = nnkBracketExpr.newTree(
        ident"array", newLit(s),
        case t
        of "uint128": ident("UInt128")
        of "uint256": ident("UInt256")
        else: ident(t)
      )
      let testStmt = quote do:
        checkBasic(`T`, dir, expectedHash)
      sizeDispatch.add nnkElifBranch.newTree(
        newCall(ident"==", size, newLit(s)),
        testStmt
      )
    sizeDispatch.add nnkElse.newTree quote do:
      raise newException(TestSizeError,
        "Unsupported **size** in type/size combination: array[" &
        $size & "," & typeIdent & ']')
    dispatcher.add nnkElifBranch.newTree(
      newCall(ident"==", typeIdent, newLit(t)),
      sizeDispatch
    )
  dispatcher.add nnkElse.newTree quote do:
    raise newException(ValueError,
      "Unsupported **type** in type/size combination: array[" &
      $`size` & ", " & `typeIdent` & ']')

  result = dispatcher
  # echo result.toStrLit() # view the generated code

proc checkVector(
    sszSubType, dir: string,
    expectedHash: SSZHashTreeRoot
) {.raises: [
    IOError, SerializationError, TestSizeError, UnconsumedInput, ValueError].} =
  var typeIdent: string
  var size: int
  let wasMatched =
    try:
      scanf(sszSubType, "vec_$+_$i", typeIdent, size)
    except ValueError:
      false  # Parsed `size` is out of range
  doAssert wasMatched
  testVector(typeIdent, size)

proc checkBitVector(
    sszSubType, dir: string,
    expectedHash: SSZHashTreeRoot
) {.raises: [IOError, SerializationError, TestSizeError, UnconsumedInput].} =
  var size: int
  let wasMatched =
    try:
      scanf(sszSubType, "bitvec_$i", size)
    except ValueError:
      false  # Parsed `size` is out of range
  doAssert wasMatched
  case size
  of 1: checkBasic(BitArray[1], dir, expectedHash)
  of 2: checkBasic(BitArray[2], dir, expectedHash)
  of 3: checkBasic(BitArray[3], dir, expectedHash)
  of 4: checkBasic(BitArray[4], dir, expectedHash)
  of 5: checkBasic(BitArray[5], dir, expectedHash)
  of 6: checkBasic(BitArray[6], dir, expectedHash)
  of 7: checkBasic(BitArray[7], dir, expectedHash)
  of 8: checkBasic(BitArray[8], dir, expectedHash)
  of 9: checkBasic(BitArray[9], dir, expectedHash)
  of 15: checkBasic(BitArray[15], dir, expectedHash)
  of 16: checkBasic(BitArray[16], dir, expectedHash)
  of 17: checkBasic(BitArray[17], dir, expectedHash)
  of 31: checkBasic(BitArray[31], dir, expectedHash)
  of 32: checkBasic(BitArray[32], dir, expectedHash)
  of 33: checkBasic(BitArray[33], dir, expectedHash)
  of 511: checkBasic(BitArray[511], dir, expectedHash)
  of 512: checkBasic(BitArray[512], dir, expectedHash)
  of 513: checkBasic(BitArray[513], dir, expectedHash)
  else:
    raise newException(TestSizeError, "Unsupported BitVector of size " & $size)

proc checkBitList(
    sszSubType, dir: string,
    expectedHash: SSZHashTreeRoot
) {.raises: [IOError, SerializationError, UnconsumedInput, ValueError].} =
  if sszSubType.startsWith("bitlist_n"):
    # Invalid data, ensure that it does not deserialize with different sizes
    checkBasic(BitList[0], dir, expectedHash)
    checkBasic(BitList[1], dir, expectedHash)
    checkBasic(BitList[2], dir, expectedHash)
    checkBasic(BitList[3], dir, expectedHash)
    checkBasic(BitList[4], dir, expectedHash)
    checkBasic(BitList[5], dir, expectedHash)
    checkBasic(BitList[6], dir, expectedHash)
    checkBasic(BitList[7], dir, expectedHash)
    checkBasic(BitList[8], dir, expectedHash)
    checkBasic(BitList[9], dir, expectedHash)
    checkBasic(BitList[15], dir, expectedHash)
    checkBasic(BitList[16], dir, expectedHash)
    checkBasic(BitList[17], dir, expectedHash)
    checkBasic(BitList[31], dir, expectedHash)
    checkBasic(BitList[32], dir, expectedHash)
    checkBasic(BitList[33], dir, expectedHash)
    checkBasic(BitList[511], dir, expectedHash)
    checkBasic(BitList[512], dir, expectedHash)
    checkBasic(BitList[513], dir, expectedHash)
    return

  var maxLen: int
  let wasMatched =
    try:
      scanf(sszSubType, "bitlist_$i", maxLen)
    except ValueError:
      false  # Parsed `size` is out of range
  doAssert wasMatched
  case maxLen
  of 0: checkBasic(BitList[0], dir, expectedHash)
  of 1: checkBasic(BitList[1], dir, expectedHash)
  of 2: checkBasic(BitList[2], dir, expectedHash)
  of 3: checkBasic(BitList[3], dir, expectedHash)
  of 4: checkBasic(BitList[4], dir, expectedHash)
  of 5: checkBasic(BitList[5], dir, expectedHash)
  of 6: checkBasic(BitList[6], dir, expectedHash)
  of 7: checkBasic(BitList[7], dir, expectedHash)
  of 8: checkBasic(BitList[8], dir, expectedHash)
  of 9: checkBasic(BitList[9], dir, expectedHash)
  of 15: checkBasic(BitList[15], dir, expectedHash)
  of 16: checkBasic(BitList[16], dir, expectedHash)
  of 17: checkBasic(BitList[17], dir, expectedHash)
  of 31: checkBasic(BitList[31], dir, expectedHash)
  of 32: checkBasic(BitList[32], dir, expectedHash)
  of 33: checkBasic(BitList[33], dir, expectedHash)
  of 511: checkBasic(BitList[511], dir, expectedHash)
  of 512: checkBasic(BitList[512], dir, expectedHash)
  of 513: checkBasic(BitList[513], dir, expectedHash)
  else:
    raise newException(ValueError, "Unsupported Bitlist of max length " & $maxLen)

# Test dispatch for valid inputs
# ------------------------------------------------------------------------

proc sszCheck(dir, sszType, sszSubType: string)
    {.raises: [IOError, OSError, SerializationError, UnconsumedInput,
               ValueError, YamlConstructionError, YamlParserError].} =
  # Hash tree root
  var expectedHash: SSZHashTreeRoot
  if fileExists(dir/"meta.yaml"):
    let s = openFileStream(dir/"meta.yaml")
    defer: close(s)
    yaml.load(s, expectedHash)

  # Deserialization and checks
  case sszType
  of "boolean": checkBasic(bool, dir, expectedHash)
  of "uints":
    var bitsize: int
    let wasMatched =
      try:
        scanf(sszSubType, "uint_$i", bitsize)
      except ValueError:
        false  # Parsed `size` is out of range
    doAssert wasMatched
    case bitsize
    of 8:   checkBasic(uint8, dir, expectedHash)
    of 16:  checkBasic(uint16, dir, expectedHash)
    of 32:  checkBasic(uint32, dir, expectedHash)
    of 64:  checkBasic(uint64, dir, expectedHash)
    of 128: checkBasic(UInt128, dir, expectedHash)
    of 256: checkBasic(UInt256, dir, expectedHash)
    else:
      raise newException(ValueError, "unknown uint in test: " & sszSubType)
  of "basic_progressive_list":
    checkProgressiveList(sszSubType, dir, expectedHash)
  of "basic_vector": checkVector(sszSubType, dir, expectedHash)
  of "bitvector": checkBitVector(sszSubType, dir, expectedHash)
  of "bitlist": checkBitList(sszSubType, dir, expectedHash)
  of "compatible_unions":
    var name: string
    let wasMatched = scanf(sszSubType, "$+_", name)
    doAssert wasMatched
    case name
    of "CompatibleUnionA": checkBasic(CompatibleUnionA, dir, expectedHash)
    of "CompatibleUnionBC": checkBasic(CompatibleUnionBC, dir, expectedHash)
    of "CompatibleUnionABCA": checkBasic(CompatibleUnionABCA, dir, expectedHash)
    else:
      raise newException(ValueError,
        "unknown compatible union in test: " & sszSubType)
  of "containers":
    var name: string
    let wasMatched = scanf(sszSubType, "$+_", name)
    doAssert wasMatched
    case name
    of "SingleFieldTestStruct": checkBasic(SingleFieldTestStruct, dir, expectedHash)
    of "SmallTestStruct": checkBasic(SmallTestStruct, dir, expectedHash)
    of "FixedTestStruct": checkBasic(FixedTestStruct, dir, expectedHash)
    of "VarTestStruct": checkBasic(VarTestStruct, dir, expectedHash)
    of "ComplexTestStruct":
      checkBasic(ComplexTestStruct, dir, expectedHash)
      checkBasic(HashArrayComplexTestStruct, dir, expectedHash)
    of "ProgressiveTestStruct":
      checkBasic(ProgressiveTestStruct, dir, expectedHash)
    of "BitsStruct": checkBasic(BitsStruct, dir, expectedHash)
    of "ProgressiveBitsStruct":
      checkBasic(ProgressiveBitsStruct, dir, expectedHash)
    else:
      raise newException(ValueError, "unknown container in test: " & sszSubType)
  of "progressive_bitlist":
    checkBasic(BitSeq, dir, expectedHash)
  of "progressive_containers":
    var name: string
    let wasMatched = scanf(sszSubType, "$+_", name)
    doAssert wasMatched
    case name
    of "ProgressiveSingleFieldContainerTestStruct":
      checkBasic(ProgressiveSingleFieldContainerTestStruct, dir, expectedHash)
    of "ProgressiveSingleListContainerTestStruct":
      checkBasic(ProgressiveSingleListContainerTestStruct, dir, expectedHash)
    of "ProgressiveVarTestStruct":
      checkBasic(ProgressiveVarTestStruct, dir, expectedHash)
    of "ProgressiveComplexTestStruct":
      checkBasic(ProgressiveComplexTestStruct, dir, expectedHash)
    else:
      raise newException(ValueError,
        "unknown progressive container in test: " & sszSubType)
  else:
    raise newException(ValueError, "unknown ssz type in test: " & sszType)

# Test dispatch for invalid inputs
# ------------------------------------------------------------------------

# TODO

# Test runner
# ------------------------------------------------------------------------

proc runValidTest(dir, sszType, sszSubType: string) =
  test &"{sszType:12} - valid - " & sszSubType:
    sszCheck(dir, sszType, sszSubType)

proc runInvalidTest(dir, sszType, sszSubType: string) =
  test &"{sszType:12} - invalid - " & sszSubType:
    try:
      sszCheck(dir, sszType, sszSubType)
    except SszError, UnconsumedInput:
      discard
    except TestSizeError as err:
      echo err.msg
      skip()
    except:
      echo getStackTrace(getCurrentException())
      echo getCurrentExceptionMsg()
      check false

suite "EF - SSZ generic types":
  doAssert dirExists(SSZDir), "You need to run the \"download_test_vectors.sh\" script to retrieve the consensus spec test vectors."
  for pathKind, sszType in walkDir(SSZDir, relative = true, checkDir = true):
    doAssert pathKind == pcDir

    block:
      let path = SSZDir/sszType/"valid"
      for pathKind, sszSubType in walkDir(
          path, relative = true, checkDir = true):
        if pathKind != pcDir: continue
        runValidTest(path/sszSubType, sszType, sszSubType)

    block:
      let path = SSZDir/sszType/"invalid"
      for pathKind, sszSubType in walkDir(
          path, relative = true, checkDir = true):
        if pathKind != pcDir: continue
        runInvalidTest(path/sszSubType, sszType, sszSubType)
