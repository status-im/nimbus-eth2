# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[os, strutils, typetraits],
  # Internals
  ../../beacon_chain/spec/[
    eth2_merkleization, eth2_ssz_serialization],
  # Status libs,
  snappy,
  stew/byteutils

export
  eth2_merkleization, eth2_ssz_serialization

# Process current EF test format
# ---------------------------------------------

# #######################
# JSON deserialization

func readValue*(r: var JsonReader, a: var seq[byte]) =
  ## Custom deserializer for seq[byte]
  a = hexToSeqByte(r.readValue(string))

# #######################
# Test helpers

type
  UnconsumedInput* = object of CatchableError
  TestSizeError* = object of ValueError

  # https://github.com/ethereum/consensus-specs/tree/v1.1.3/tests/formats/rewards#rewards-tests
  Deltas* = object
    rewards*: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]
    penalties*: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.4/specs/phase0/validator.md#eth1block
  Eth1Block* = object
    timestamp*: uint64
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    # All other eth1 block fields

const
  FixturesDir* =
    currentSourcePath.rsplit(DirSep, 1)[0] / ".." / ".." / "vendor" / "nim-eth2-scenarios"
  SszTestsDir* = FixturesDir / "tests-v1.1.4"
  MaxObjectSize* = 3_000_000

proc parseTest*(path: string, Format: typedesc[Json], T: typedesc): T =
  try:
    # debugEcho "          [Debug] Loading file: \"", path, '\"'
    result = Format.loadFile(path, T)
  except SerializationError as err:
    writeStackTrace()
    stderr.write $Format & " load issue for file \"", path, "\"\n"
    stderr.write err.formatMsg(path), "\n"
    quit 1

template readFileBytes*(path: string): seq[byte] =
  cast[seq[byte]](readFile(path))

proc sszDecodeEntireInput*(input: openArray[byte], Decoded: type): Decoded =
  var stream = unsafeMemoryInput(input)
  var reader = init(SszReader, stream)
  reader.readValue(result)

  if stream.readable:
    raise newException(UnconsumedInput, "Remaining bytes in the input")

iterator walkTests*(dir: static string): string =
   for kind, path in walkDir(
       dir/"pyspec_tests", relative = true, checkDir = true):
     yield path

proc parseTest*(path: string, Format: typedesc[SSZ], T: typedesc): T =
  try:
    # debugEcho "          [Debug] Loading file: \"", path, '\"'
    sszDecodeEntireInput(snappy.decode(readFileBytes(path), MaxObjectSize), T)
  except SerializationError as err:
    writeStackTrace()
    stderr.write $Format & " load issue for file \"", path, "\"\n"
    stderr.write err.formatMsg(path), "\n"
    quit 1
