# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  # Standard library
  std/[strutils, typetraits],
  # Internals
  ./os_ops,
  ../../beacon_chain/spec/datatypes/[phase0, altair, bellatrix],
  ../../beacon_chain/spec/[
    eth2_merkleization, eth2_ssz_serialization, forks, helpers],
  # Status libs,
  snappy,
  stew/byteutils

export
  eth2_merkleization, eth2_ssz_serialization, helpers

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
  of ConsensusFork.Electra:
    res.ELECTRA_FORK_EPOCH = GENESIS_EPOCH
    res.DENEB_FORK_EPOCH = GENESIS_EPOCH
    res.CAPELLA_FORK_EPOCH = GENESIS_EPOCH
    res.BELLATRIX_FORK_EPOCH = GENESIS_EPOCH
    res.ALTAIR_FORK_EPOCH = GENESIS_EPOCH
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
    rewards*: List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]
    penalties*: List[Gwei, Limit VALIDATOR_REGISTRY_LIMIT]

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.6/specs/phase0/validator.md#eth1block
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

proc relativeTestPathComponent*(path: string, suitePath = SszTestsDir): string =
  try:
    path.relativePath(suitePath)
  except Exception as exc:
    raiseAssert "relativePath failed unexpectedly: " & $exc.msg

proc parseTest*(path: string, Format: typedesc[Json], T: typedesc): T =
  try:
    # debugEcho "          [Debug] Loading file: \"", path, '\"'
    result = Format.decode(readFileBytes(path), T)
  except SerializationError as err:
    writeStackTrace()
    try:
      stderr.write $Format & " load issue for file \"", path, "\"\n"
      stderr.write err.formatMsg(path), "\n"
    except IOError:
      discard
    quit 1

proc sszDecodeEntireInput*(
    input: openArray[byte],
    Decoded: type
): Decoded {.raises: [IOError, SerializationError, UnconsumedInput].} =
  let stream = unsafeMemoryInput(input)
  var reader = init(SszReader, stream)
  reader.readValue(result)

  if stream.readable:
    raise newException(UnconsumedInput, "Remaining bytes in the input")

iterator walkTests*(dir: static string): string {.raises: [OSError].} =
   for kind, path in walkDir(
       dir/"pyspec_tests", relative = true, checkDir = true):
     yield path

proc parseTest*(path: string, Format: typedesc[SSZ], T: typedesc): T =
  try:
    # debugEcho "          [Debug] Loading file: \"", path, '\"'
    sszDecodeEntireInput(snappy.decode(readFileBytes(path), MaxObjectSize), T)
  except IOError as err:
    writeStackTrace()
    try:
      stderr.write $Format & " load issue for file \"", path, "\"\n"
      stderr.write "IOError: " & err.msg, "\n"
    except IOError:
      discard
    quit 1
  except SerializationError as err:
    writeStackTrace()
    try:
      stderr.write $Format & " load issue for file \"", path, "\"\n"
      stderr.write err.formatMsg(path), "\n"
    except IOError:
      discard
    quit 1
  except UnconsumedInput as err:
    writeStackTrace()
    try:
      stderr.write $Format & " load issue for file \"", path, "\"\n"
      stderr.write "UnconsumedInput: " & err.msg, "\n"
    except IOError:
      discard
    quit 1

proc loadForkedState*(
    path: string, consensusFork: ConsensusFork): ref ForkedHashedBeaconState =
  let state = (ref ForkedHashedBeaconState)(kind: consensusFork)
  withState(state[]):
    forkyState.data = parseTest(path, SSZ, consensusFork.BeaconState)
    forkyState.root = hash_tree_root(forkyState.data)
  state

proc loadBlock*(
    path: string,
    consensusFork: static ConsensusFork,
    validateBlockHash = true): auto =
  var blck = parseTest(path, SSZ, consensusFork.SignedBeaconBlock)
  blck.root = hash_tree_root(blck.message)
  when consensusFork >= ConsensusFork.Bellatrix:
    if blck.message.is_execution_block:
      if blck.message.body.execution_payload.block_hash !=
          blck.message.compute_execution_block_hash():
        try:
          stderr.write "Invalid `block_hash`: ", path, "\n"
        except IOError:
          discard
        quit 1
  blck
