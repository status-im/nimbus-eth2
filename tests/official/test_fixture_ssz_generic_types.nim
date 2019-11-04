# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, unittest, strutils, streams, strformat, strscans,
  # Status libraries
  stint,
  # Third-party
  yaml,
  # Beacon chain internals
  ../../beacon_chain/spec/[datatypes, digest],
  ../../beacon_chain/ssz,
  # Test utilities
  ../testutil

const
  FixturesDir = currentSourcePath.rsplit(DirSep, 1)[0] / "fixtures"
  SSZDir = FixturesDir/"tests-v0.9.0"/"general"/"phase0"/"ssz_generic"



type
  SszKind = enum
    Basic
    Complex

  SSZHashTreeRoot = object
    # The test files have the values at the "root"
    # so we **must** use "root" as a field name
    root: string
    # Containers have a root (thankfully) and signing_root field
    signing_root: string

# Make signing root optional
setDefaultValue(SSZHashTreeRoot, signing_root, "")

template checkT(T:typedesc) {.dirty.}=
  let deserialized = SSZ.loadFile(dir/"serialized.ssz", T)
  check:
    expectedHash.root == "0x" & toLowerASCII($deserialized.hashTreeRoot())

proc sszCheck(sszType, sszSubType: string) =
  let dir = SSZDir/sszType/"valid"/sszSubType

  # Hash tree root
  var expectedHash: SSZHashTreeRoot
  var s = openFileStream(dir/"meta.yaml")
  yaml.load(s, expectedHash)
  s.close()

  # Deserialization and checks
  case sszType
  of "boolean": checkT(bool)
  of "uints":
    var bitsize: int
    let wasMatched = scanf(sszSubType, "uint_$i", bitsize)
    assert wasMatched
    case bitsize
    of 8:  checkT(uint8)
    of 16: checkT(uint16)
    of 32: checkT(uint32)
    of 64: checkT(uint64)
    of 128: discard # checkT(Stuint[128]) # TODO
    of 256: discard # checkT(Stuint[256])
    else:
      raise newException(ValueError, "unknown uint in test: " & sszSubType)
  else:
    discard # TODO

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
