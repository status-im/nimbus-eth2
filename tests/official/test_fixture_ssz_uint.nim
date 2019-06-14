# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  ospaths, strutils, unittest, sequtils,
  # Status libs
  stint, serialization,
  # Beacon chain internals
  ../../beacon_chain/ssz,
  ../../beacon_chain/spec/[datatypes, validator],
  # Test utilities
  ../testutil,
  ./fixtures_utils

type
  SSZUint* = object
    `type`*: string
    value*: string
    valid*: bool
    ssz*: seq[byte]
    tags*: seq[string]

const TestFolder = currentSourcePath.rsplit(DirSep, 1)[0]
const TestsPath = "fixtures" / "json_tests" / "ssz_generic" / "uint"

func to(val: string, T: typedesc): T =
  when T is StUint:
    val.parse(T)
  else: # result is unsigned int
    val.parse(StUint[8 * sizeof(T)]).data

# TODO strformat for the skipped checks

template checkSerialization(test: SSZUint, T: typedesc) =
  if test.valid:
    let value: T = test.value.to(T)
    let serialized = SSZ.encode(value)
    check(serialized == test.ssz)
  elif test.value != "":
    # No SSZ encoding -> expected failing serialization test
    if test.tags.anyIt(it == "uint_underflow"):
      # TODO: Stint throws RangeError for negative number parsing
      #       https://github.com/status-im/nim-stint/blob/ccf87daac1eef15238ff3d6d2edb138e22180d19/stint/io.nim#L130-L132
      # TODO: Stint checks with an assert that integer is positive or zero
      #       https://github.com/status-im/nim-stint/blob/ccf87daac1eef15238ff3d6d2edb138e22180d19/stint/io.nim#L35
      expect RangeError, OverflowError, AssertionError:
        let value: T = test.value.to(T)
    else:
      # TODO tag "uint_overflow" does not throw an exception at the moment
      echo "         [Skipped - Serialization - TODO]  tags: ", test.tags
  else:
    echo "         [Skipped - Serialization - N/A]   tags: ", test.tags

template checkDeserialization(test: SSZUint, T: typedesc) =
  if test.valid:
    let deser = SSZ.decode(test.ssz, T)
    check($deser == test.value)
  elif test.value == "":
    # No literal value -> expected failing deserialization test
    if test.tags.anyIt(it == "wrong_length"):
      expect IndexError:
        let deser = SSZ.decode(test.ssz, T)
    else:
      echo "         [Skipped - Deserialization]       tags: ", test.tags
  else:
    echo "         [Skipped - Deserialization - N/A] tags: ", test.tags

proc runSSZUintTest(inputTests: Tests[SSZUint]) =
  # We use Stint string -> uint parser + casting
  # as it's generic over all unsigned integer size
  # and not just BiggestUint
  for test in inputTests.test_cases:
    if test.`type` == "uint8":
      test.checkSerialization(uint8)
      test.checkDeserialization(uint8)
    elif test.`type` == "uint16":
      test.checkSerialization(uint16)
      test.checkDeserialization(uint16)
    elif test.`type` == "uint32":
      test.checkSerialization(uint32)
      test.checkDeserialization(uint32)
    elif test.`type` == "uint64":
      test.checkSerialization(uint64)
      test.checkDeserialization(uint64)
    # TODO: Stint serialization
    # elif test.`type` == "uint128":
    #   test.checkSerialization(StUint[128])
    # elif test.`type` == "uint256":
    #   test.checkSerialization(StUint[256])
    else:
      echo "         [Skipped] uint size: ", test.`type`

suite "Official - SSZ unsigned integer tests" & preset():
  block: # "Integers right at or beyond the bounds of the allowed value range"
    let uintBounds = parseTests(TestFolder / TestsPath / "uint_bounds.json", SSZUint)
    test uintBounds.summary & preset():
      runSSZUintTest(uintBounds)

  block: # "Random integers chosen uniformly over the allowed value range"
    let uintRandom = parseTests(TestFolder / TestsPath / "uint_random.json", SSZUint)
    test uintRandom.summary & preset():
      runSSZUintTest(uintRandom)

  # TODO: pending fix for https://github.com/status-im/nim-beacon-chain/issues/280
  block: # "Serialized integers that are too short or too long"
    let uintWrongLength = parseTests(TestFolder / TestsPath / "uint_wrong_length.json", SSZUint)
    test "[Skipped] " & uintWrongLength.summary & preset():
      # TODO: pending fix for https://github.com/status-im/nim-beacon-chain/issues/280
      echo "         [Skipped] Pending https://github.com/status-im/nim-beacon-chain/issues/280"
      # runSSZUintTest(uintWrongLength)
