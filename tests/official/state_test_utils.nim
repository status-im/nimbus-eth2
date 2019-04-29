import
  # Status libs
  blscurve, nimcrypto, byteutils,
  eth/common, serialization, json_serialization,
  # Beacon chain internals
  # submodule in nim-beacon-chain/tests/official/fixtures/
  ../../beacon_chain/spec/[datatypes, crypto, digest]

export nimcrypto.toHex

type
  # TODO: use ref object to avoid allocating
  #       so much on the stack - pending https://github.com/status-im/nim-json-serialization/issues/3
  StateTest* = object
    title*: string
    summary*: string
    test_suite*: string
    fork*: string
    test_cases*: seq[TestCase]
  
  TestConstants* = object
    SHARD_COUNT*: int
    TARGET_COMMITTEE_SIZE*: int
    MAX_BALANCE_CHURN_QUOTIENT*: int
    MAX_INDICES_PER_ATTESTATION*: int
    MIN_PER_EPOCH_CHURN_LIMIT*: int
    SHUFFLE_ROUND_COUNT*: int
    DEPOSIT_CONTRACT_TREE_DEPTH*: int
    MIN_DEPOSIT_AMOUNT*: uint64
    MAX_EFFECTIVE_BALANCE*: uint64
    FORK_CHOICE_BALANCE_INCREMENT*: uint64
    EJECTION_BALANCE*: uint64
    GENESIS_FORK_VERSION*: uint32
    GENESIS_SLOT*: Slot
    GENESIS_EPOCH*: Epoch
    GENESIS_START_SHARD*: uint64
    BLS_WITHDRAWAL_PREFIX_BYTE*: array[1, byte]
    SECONDS_PER_SLOT*: uint64
    MIN_ATTESTATION_INCLUSION_DELAY*: uint64
    SLOTS_PER_EPOCH*: int
    MIN_SEED_LOOKAHEAD*: int
    ACTIVATION_EXIT_DELAY*: int
    EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64
    SLOTS_PER_HISTORICAL_ROOT*: int
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY*: uint64
    PERSISTENT_COMMITTEE_PERIOD*: uint64
    LATEST_RANDAO_MIXES_LENGTH*: int
    LATEST_ACTIVE_INDEX_ROOTS_LENGTH*: int
    LATEST_SLASHED_EXIT_LENGTH*: int
    BASE_REWARD_QUOTIENT*: uint64
    WHISTLEBLOWER_REWARD_QUOTIENT*: uint64
    ATTESTATION_INCLUSION_REWARD_QUOTIENT*: uint64
    INACTIVITY_PENALTY_QUOTIENT*: uint64
    MIN_PENALTY_QUOTIENT*: int
    MAX_PROPOSER_SLASHINGS*: int
    MAX_ATTESTER_SLASHINGS*: int
    MAX_ATTESTATIONS*: int
    MAX_DEPOSITS*: int
    MAX_VOLUNTARY_EXITS*: int
    MAX_TRANSFERS*: int
    DOMAIN_BEACON_PROPOSER*: SignatureDomain
    DOMAIN_RANDAO*: SignatureDomain
    DOMAIN_ATTESTATION*: SignatureDomain
    DOMAIN_DEPOSIT*: SignatureDomain
    DOMAIN_VOLUNTARY_EXIT*: SignatureDomain
    DOMAIN_TRANSFER*: SignatureDomain

  TestCase* = object
    name*: string
    config*: TestConstants
    verify_signatures*: bool
    initial_state*: BeaconState
    blocks*: seq[BeaconBlock]
    expected_state*: ExpectedState
  
  ExpectedState* = object
    ## TODO what is this?
    slot*: Slot

# #######################
# Default init
proc default*(T: typedesc): T = discard

# #######################
# JSON deserialization

proc readValue*[N: static int](r: var JsonReader, a: var array[N, byte]) {.inline.} =
  # Needed for;
  #   - BLS_WITHDRAWAL_PREFIX_BYTE
  #   - FOrk datatypes
  # TODO: are all bytes and bytearray serialized as hex?
  #       if so export that to nim-eth
  hexToByteArray(r.readValue(string), a)

proc parseStateTests*(jsonPath: string): StateTest =
  try:
    result = Json.loadFile(jsonPath, StateTest)
  except SerializationError as err:
    writeStackTrace()
    stderr.write "Json load issue for file \"", jsonPath, "\"\n"
    stderr.write err.formatMsg(jsonPath), "\n"
    quit 1