import
  # Status libs
  blscurve, nimcrypto, byteutils,
  eth/common, serialization, json_serialization,
  # Beacon chain internals
  # submodule in nim-beacon-chain/tests/official/fixtures/
  ../../beacon_chain/spec/[datatypes, crypto, digest],
  ../../beacon_chain/ssz,
  # Workarounds
  endians # parseHex into uint64

export nimcrypto.toHex

type
  # TODO: use ref object to avoid allocating
  #       so much on the stack - pending https://github.com/status-im/nim-json-serialization/issues/3
  StateTests* = object
    title*: string
    summary*: string
    test_suite*: string
    fork*: string
    test_cases*: seq[StateTestCase]
  
  TestConstants* = object
    # TODO - 0.5.1 constants
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
    PROPOSER_REWARD_QUOTIENT*: uint64
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

  StateTestCase* = object
    name*: string
    config*: TestConstants
    verify_signatures*: bool
    initial_state*: BeaconState
    blocks*: seq[BeaconBlock]
    expected_state*: BeaconState

  Tests*[T] = object
    title*: string
    summary*: string
    forks_timeline*: string
    forks*: seq[string]
    config*: string
    runner*: string
    handler*: string
    test_cases*: seq[T]

  Shuffling* = object
    seed*: Eth2Digest
    count*: uint64
    shuffled*: seq[ValidatorIndex]

  # # TODO - but already tested in nim-blscurve
  # BLSUncompressedG2 = object
  #   input*: tuple[
  #     message: seq[byte],
  #     domain: array[1, byte]
  #     ]
  #   output*: ECP2_BLS381

  # # TODO - but already tested in nim-blscurve
  # BLSCompressedG2 = object
  #   input*: tuple[
  #     message: seq[byte],
  #     domain: array[1, byte]
  #     ]
  #   output*: ECP2_BLS381

  Domain = distinct uint64
    ## Domains have custom hex serialization
    
  BLSPrivToPub* = object
    input*: ValidatorPrivKey
    output*: ValidatorPubKey

  BLSSignMsgInput = object
    privkey*: ValidatorPrivKey
    message*: seq[byte]
    domain*: Domain

  BLSSignMsg* = object
    input*: BLSSignMsgInput
    output*: Signature
  
# #######################
# Default init
proc default*(T: typedesc): T = discard

# #######################
# JSON deserialization

proc readValue*[N: static int](r: var JsonReader, a: var array[N, byte]) {.inline.} =
  # Needed for;
  #   - BLS_WITHDRAWAL_PREFIX_BYTE
  #   - Fork datatypes
  # TODO: are all bytes and bytearray serialized as hex?
  #       if so export that to nim-eth
  hexToByteArray(r.readValue(string), a)

proc readValue*(r: var JsonReader, a: var ValidatorIndex) {.inline.} =
  a = r.readValue(uint32)

proc readValue*(r: var JsonReader, a: var Domain) {.inline.} =
  ## Custom deserializer for Domain
  ## They are uint64 stored in hex values
  # Furthermore Nim parseHex doesn't support uint
  # until https://github.com/nim-lang/Nim/pull/11067
  # (0.20)
  let be_uint = hexToPaddedByteArray[8](r.readValue(string))
  bigEndian64(a.addr, be_uint.unsafeAddr)

proc readValue*(r: var JsonReader, a: var seq[byte]) {.inline.} =
  ## Custom deserializer for Domain
  ## They are uint64 stored in hex values
  # Furthermore Nim parseHex doesn't support uint
  # until https://github.com/nim-lang/Nim/pull/11067
  # (0.20)
  a = hexToSeqByte(r.readValue(string))

# TODO: workaround https://github.com/status-im/nim-serialization/issues/4
#       and https://github.com/status-im/nim-serialization/issues/5

proc parseTestsShuffling*(jsonPath: string): Tests[Shuffling] =
  try:
    result = Json.loadFile(jsonPath, Tests[Shuffling])
  except SerializationError as err:
    writeStackTrace()
    stderr.write "Json load issue for file \"", jsonPath, "\"\n"
    stderr.write err.formatMsg(jsonPath), "\n"
    quit 1

proc parseTestsBLSPrivToPub*(jsonPath: string): Tests[BLSPrivToPub] =
  try:
    result = Json.loadFile(jsonPath, Tests[BLSPrivToPub])
  except SerializationError as err:
    writeStackTrace()
    stderr.write "Json load issue for file \"", jsonPath, "\"\n"
    stderr.write err.formatMsg(jsonPath), "\n"
    quit 1

proc parseTestsBLSSignMsg*(jsonPath: string): Tests[BLSSignMsg] =
  try:
    result = Json.loadFile(jsonPath, Tests[BLSSignMsg])
  except SerializationError as err:
    writeStackTrace()
    stderr.write "Json load issue for file \"", jsonPath, "\"\n"
    stderr.write err.formatMsg(jsonPath), "\n"
    quit 1

# #######################
# Mocking helpers
# https://github.com/ethereum/eth2.0-specs/blob/75f0af45bb0613bb406fc72d10266cee4cfb402a/tests/phase0/helpers.py#L107

proc build_empty_block_for_next_slot*(state: BeaconState): BeaconBlock =
  ## TODO: why can the official spec get away with a simple proc

  # result.slot = state.slot + 1
  # var previous_block_header = state.latest_block_header
  # if previous_block_header.state_root == ZERO_HASH:
  #   previous_block_header.state_root = state.hash_tree_root()
  # result.previous_block_root = signing_root(previous_block_header)

  ## TODO: `makeBlock` from testutil.nim
  ##       doesn't work either due to use of fake private keys

  # let prev_root = block:
  #   if state.latest_block_header.state_root == ZERO_HASH:
  #     state.hash_tree_root()
  #   else: state.latest_block_header.state_root
  # result = makeBlock(
  #   state,
  #   prev_root,
  #   BeaconBlockBody()
  # )
  {.error: "Not implemented".}