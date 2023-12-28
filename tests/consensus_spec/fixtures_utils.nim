# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  std/[strutils, typetraits],
  # Internals
  ./os_ops,
  ../../beacon_chain/spec/datatypes/[phase0, altair, bellatrix],
  ../../beacon_chain/spec/[
    eth2_merkleization, eth2_ssz_serialization, forks],
  # Status libs,
  snappy,
  stew/byteutils

export
  eth2_merkleization, eth2_ssz_serialization

# Process current EF test format
# ---------------------------------------------

# #######################
# Path parsing

func forkForPathComponent*(forkPath: string): Opt[ConsensusFork] =
  for fork in ConsensusFork:
    if ($fork).toLowerAscii() == forkPath:
      return ok fork
  err()

# #######################
# JSON deserialization

func readValue*(r: var JsonReader, a: var seq[byte]) =
  ## Custom deserializer for seq[byte]
  a = hexToSeqByte(r.readValue(string))

# #######################
# Mock RuntimeConfig

func genesisTestRuntimeConfig*(consensusFork: ConsensusFork): RuntimeConfig =
  var res = defaultRuntimeConfig
  case consensusFork
  of ConsensusFork.Deneb:
    res.DENEB_FORK_EPOCH = GENESIS_EPOCH
    res.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
    res.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
  of ConsensusFork.Capella:
    res.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
    res.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
  of ConsensusFork.Bellatrix:
    res.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
  of ConsensusFork.Altair:
    res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
  of ConsensusFork.Phase0:
    discard
  res

# #######################
# Test helpers

type
  UnconsumedInput* = object of CatchableError
  TestSizeError* = object of ValueError

  # https://github.com/ethereum/consensus-specs/tree/v1.3.0/tests/formats/rewards#rewards-tests
  Deltas* = object
    rewards*: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]
    penalties*: List[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/phase0/validator.md#eth1block
  Eth1Block* = object
    timestamp*: uint64
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    # All other eth1 block fields

const
  FixturesDir* =
    currentSourcePath.rsplit(DirSep, 1)[0] / ".." / ".." / "vendor" / "nim-eth2-scenarios"
  SszTestsDir* = FixturesDir / "tests-v" & SPEC_VERSION
  MaxObjectSize* = 3_000_000

proc parseTest*(path: string, Format: typedesc[Json], T: typedesc): T =
  try:
    # debugEcho "          [Debug] Loading file: \"", path, '\"'
    result = Format.decode(readFileBytes(path), T)
  except SerializationError as err:
    writeStackTrace()
    stderr.write $Format & " load issue for file \"", path, "\"\n"
    stderr.write err.formatMsg(path), "\n"
    quit 1

proc sszDecodeEntireInput*(input: openArray[byte], Decoded: type): Decoded =
  let stream = unsafeMemoryInput(input)
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

from ../../beacon_chain/spec/datatypes/capella import BeaconState
from ../../beacon_chain/spec/datatypes/deneb import BeaconState

proc loadForkedState*(
    path: string, fork: ConsensusFork): ref ForkedHashedBeaconState =
  var forkedState: ref ForkedHashedBeaconState
  case fork
  of ConsensusFork.Deneb:
    let state = newClone(parseTest(path, SSZ, deneb.BeaconState))
    forkedState = (ref ForkedHashedBeaconState)(kind: ConsensusFork.Deneb)
    forkedState.denebData.data = state[]
    forkedState.denebData.root = hash_tree_root(state[])
  of ConsensusFork.Capella:
    let state = newClone(parseTest(path, SSZ, capella.BeaconState))
    forkedState = (ref ForkedHashedBeaconState)(kind: ConsensusFork.Capella)
    forkedState.capellaData.data = state[]
    forkedState.capellaData.root = hash_tree_root(state[])
  of ConsensusFork.Bellatrix:
    let state = newClone(parseTest(path, SSZ, bellatrix.BeaconState))
    forkedState = (ref ForkedHashedBeaconState)(kind: ConsensusFork.Bellatrix)
    forkedState.bellatrixData.data = state[]
    forkedState.bellatrixData.root = hash_tree_root(state[])
  of ConsensusFork.Altair:
    let state = newClone(parseTest(path, SSZ, altair.BeaconState))
    forkedState = (ref ForkedHashedBeaconState)(kind: ConsensusFork.Altair)
    forkedState.altairData.data = state[]
    forkedState.altairData.root = hash_tree_root(state[])
  of ConsensusFork.Phase0:
    let state = newClone(parseTest(path, SSZ, phase0.BeaconState))
    forkedState = (ref ForkedHashedBeaconState)(kind: ConsensusFork.Phase0)
    forkedState.phase0Data.data = state[]
    forkedState.phase0Data.root = hash_tree_root(state[])
  forkedState
