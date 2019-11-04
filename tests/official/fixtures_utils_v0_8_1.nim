# beacon_chain
# Copyright (c) 2018-Present Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  # Standard library
  os, strutils,
  # Status libs
  stew/byteutils,
  serialization, json_serialization,
  # Beacon chain internals
  ../../beacon_chain/spec/datatypes

export  # Workaround:
  #   - https://github.com/status-im/nim-serialization/issues/4
  #   - https://github.com/status-im/nim-serialization/issues/5
  #   - https://github.com/nim-lang/Nim/issues/11225
  serialization.readValue

# Process legacy EF test format (up to 0.8.1)
# -------------------------------------------

type
  # TODO: use ref object to avoid allocating
  #       so much on the stack - pending https://github.com/status-im/nim-json-serialization/issues/3

  TestConstants* = object
    SHARD_COUNT*: int
    TARGET_COMMITTEE_SIZE*: int
    MAX_BALANCE_CHURN_QUOTIENT*: int
    MAX_VALIDATORS_PER_COMMITTEE*: int
    MIN_PER_EPOCH_CHURN_LIMIT*: int
    SHUFFLE_ROUND_COUNT*: int
    DEPOSIT_CONTRACT_TREE_DEPTH*: int
    MIN_DEPOSIT_AMOUNT*: uint64
    MAX_EFFECTIVE_BALANCE*: uint64
    EJECTION_BALANCE*: uint64
    GENESIS_FORK_VERSION*: uint32
    GENESIS_SLOT*: Slot
    GENESIS_EPOCH*: Epoch
    GENESIS_START_SHARD*: uint64
    BLS_WITHDRAWAL_PREFIX*: array[1, byte]
    SECONDS_PER_SLOT*: uint64
    MIN_ATTESTATION_INCLUSION_DELAY*: uint64
    SLOTS_PER_EPOCH*: int
    MIN_SEED_LOOKAHEAD*: int
    MAX_SEED_LOOKAHEAD*: int
    EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64
    SLOTS_PER_HISTORICAL_ROOT*: int
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY*: uint64
    PERSISTENT_COMMITTEE_PERIOD*: uint64
    LATEST_RANDAO_MIXES_LENGTH*: int
    EPOCHS_PER_HISTORICAL_VECTOR*: int
    EPOCHS_PER_SLASHINGS_VECTOR*: int
    BASE_REWARD_FACTOR*: uint64
    WHISTLEBLOWER_REWARD_QUOTIENT*: uint64
    PROPOSER_REWARD_QUOTIENT*: uint64
    INACTIVITY_PENALTY_QUOTIENT*: uint64
    MIN_SLASHING_PENALTY_QUOTIENT*: int
    MAX_PROPOSER_SLASHINGS*: int
    MAX_ATTESTER_SLASHINGS*: int
    MAX_ATTESTATIONS*: int
    MAX_DEPOSITS*: int
    MAX_VOLUNTARY_EXITS*: int
    MAX_TRANSFERS*: int
    DOMAIN_BEACON_PROPOSER*: DomainType
    DOMAIN_RANDAO*: DomainType
    DOMAIN_BEACON_ATTESTER*: DomainType
    DOMAIN_DEPOSIT*: DomainType
    DOMAIN_VOLUNTARY_EXIT*: DomainType
    DOMAIN_TRANSFER*: DomainType

  Tests*[T] = object
    title*: string
    summary*: string
    forks_timeline*: string
    forks*: seq[string]
    config*: string
    runner*: string
    handler*: string
    test_cases*: seq[T]

const
  FixturesDir* = currentSourcePath.rsplit(DirSep, 1)[0] / "fixtures"
  JsonTestsDir* = FixturesDir / "json_tests_v0.8.1"

# #######################
# Default init
proc default*(T: typedesc): T = discard

# #######################
# JSON deserialization

proc readValue*[N: static int](r: var JsonReader, a: var array[N, byte]) {.inline.} =
  # Needed for;
  #   - BLS_WITHDRAWAL_PREFIX
  #   - Fork datatypes
  # TODO: are all bytes and bytearray serialized as hex?
  #       if so export that to nim-eth
  hexToByteArray(r.readValue(string), a)

proc readValue*(r: var JsonReader, a: var seq[byte]) {.inline.} =
  ## Custom deserializer for seq[byte]
  a = hexToSeqByte(r.readValue(string))

proc parseTests*(jsonPath: string, T: typedesc): Tests[T] =
  try:
    debugEcho "          [Debug] Loading file: \"", jsonPath, '\"'
    result = Json.loadFile(jsonPath, Tests[T])
  except SerializationError as err:
    writeStackTrace()
    stderr.write "Json load issue for file \"", jsonPath, "\"\n"
    stderr.write err.formatMsg(jsonPath), "\n"
    quit 1
