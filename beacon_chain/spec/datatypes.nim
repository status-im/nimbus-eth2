# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This file contains data types that are part of the spec and thus subject to
# serialization and spec updates.
#
# The spec folder in general contains code that has been hoisted from the
# specification and that follows the spec as closely as possible, so as to make
# it easy to keep up-to-date.
#
# These datatypes are used as specifications for serialization - thus should not
# be altered outside of what the spec says. Likewise, they should not be made
# `ref` - this can be achieved by wrapping them in higher-level
# types / composition

{.push raises: [Defect].}

import
  macros, hashes, json, strutils, tables, typetraits,
  stew/[byteutils], chronicles,
  json_serialization/types as jsonTypes,
  ../version, ../ssz/types as sszTypes, ./crypto, ./digest, ./presets

export
  sszTypes, presets

# TODO Data types:
# Presently, we're reusing the data types from the serialization (uint64) in the
# objects we pass around to the beacon chain logic, thus keeping the two
# similar. This is convenient for keeping up with the specification, but
# will eventually need a more robust approach such that we don't run into
# over- and underflows.
# Some of the open questions are being tracked here:
# https://github.com/ethereum/eth2.0-specs/issues/224
#
# The present approach causes some problems due to how Nim treats unsigned
# integers - here's no high(uint64), arithmetic support is incomplete, there's
# no over/underflow checking available
#
# Eventually, we could also differentiate between user/tainted data and
# internal state that's gone through sanity checks already.

const
  SPEC_VERSION* = "0.12.2" ## \
  ## Spec version we're aiming to be compatible with, right now

  GENESIS_SLOT* = Slot(0)
  GENESIS_EPOCH* = (GENESIS_SLOT.uint64 div SLOTS_PER_EPOCH).Epoch ##\
  ## compute_epoch_at_slot(GENESIS_SLOT)

  FAR_FUTURE_EPOCH* = (not 0'u64).Epoch # 2^64 - 1 in spec

  # Not part of spec. Still useful, pending removing usage if appropriate.
  ZERO_HASH* = Eth2Digest()

  # Not part of spec
  WEAK_SUBJECTVITY_PERIOD* =
    Slot(uint64(4 * 30 * 24 * 60 * 60) div SECONDS_PER_SLOT)
    # TODO: This needs revisiting.
    # Why was the validator WITHDRAWAL_PERIOD altered in the spec?

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#configuration
  ATTESTATION_PROPAGATION_SLOT_RANGE* = 32

  SLOTS_PER_ETH1_VOTING_PERIOD* = EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH

  DEPOSIT_CONTRACT_TREE_DEPTH* = 32
  BASE_REWARDS_PER_EPOCH* = 4

template maxSize*(n: int) {.pragma.}

type
  # Domains
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#domain-types
  DomainType* = enum
    DOMAIN_BEACON_PROPOSER = 0
    DOMAIN_BEACON_ATTESTER = 1
    DOMAIN_RANDAO = 2
    DOMAIN_DEPOSIT = 3
    DOMAIN_VOLUNTARY_EXIT = 4
    DOMAIN_SELECTION_PROOF = 5
    DOMAIN_AGGREGATE_AND_PROOF = 6

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#custom-types
  Domain* = array[32, byte]

  # https://github.com/nim-lang/Nim/issues/574 and be consistent across
  # 32-bit and 64-bit word platforms.
  # TODO VALIDATOR_REGISTRY_LIMIT is 1 shl 40 in 0.12.1, and
  # proc newSeq(typ: PNimType, len: int): pointer {.compilerRtl.}
  # in Nim/lib/system/gc.nim quite tightly ties seq addressibility
  # to the system wordsize. This lifts smaller, and now incorrect,
  # range-limit.
  ValidatorIndex* = distinct uint32
  Gwei* = uint64
  CommitteeIndex* = distinct uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#proposerslashing
  ProposerSlashing* = object
    signed_header_1*: SignedBeaconBlockHeader
    signed_header_2*: SignedBeaconBlockHeader

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#attesterslashing
  AttesterSlashing* = object
    attestation_1*: IndexedAttestation
    attestation_2*: IndexedAttestation

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#indexedattestation
  IndexedAttestation* = object
    # TODO ValidatorIndex, but that doesn't serialize properly
    attesting_indices*: List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE]
    data*: AttestationData
    signature*: ValidatorSig

  TrustedIndexedAttestation* = object
    # TODO ValidatorIndex, but that doesn't serialize properly
    attesting_indices*: List[uint64, Limit MAX_VALIDATORS_PER_COMMITTEE]
    data*: AttestationData
    signature*: TrustedSig

  CommitteeValidatorsBits* = BitList[Limit MAX_VALIDATORS_PER_COMMITTEE]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#attestation
  Attestation* = object
    aggregation_bits*: CommitteeValidatorsBits
    data*: AttestationData
    signature*: ValidatorSig

  TrustedAttestation* = object
    aggregation_bits*: CommitteeValidatorsBits
    data*: AttestationData
    signature*: TrustedSig

  ForkDigest* = distinct array[4, byte]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#forkdata
  ForkData* = object
    current_version*: Version
    genesis_validators_root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#checkpoint
  Checkpoint* = object
    epoch*: Epoch
    root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#AttestationData
  AttestationData* = object
    slot*: Slot

    # TODO this is actually a CommitteeIndex; remove some conversions by
    # allowing SSZ to directly handle this
    index*: uint64

    # LMD GHOST vote
    beacon_block_root*: Eth2Digest

    # FFG vote
    source*: Checkpoint
    target*: Checkpoint

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#deposit
  Deposit* = object
    proof*: array[DEPOSIT_CONTRACT_TREE_DEPTH + 1, Eth2Digest] ##\
    ## Merkle path to deposit root

    data*: DepositData

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#depositmessage
  DepositMessage* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#depositdata
  DepositData* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei
    # Cannot use TrustedSig here as invalid signatures are possible and determine
    # if the deposit should be added or not during processing
    signature*: ValidatorSig  # Signing over DepositMessage

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#voluntaryexit
  VoluntaryExit* = object
    epoch*: Epoch ##\
    ## Earliest epoch when voluntary exit can be processed

    validator_index*: uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot
    proposer_index*: uint64

    parent_root*: Eth2Digest ##\
    ## Root hash of the previous block

    state_root*: Eth2Digest ##\
    ## The state root, _after_ this block has been processed

    body*: BeaconBlockBody

  TrustedBeaconBlock* = object
    ## When we receive blocks from outside sources, they are untrusted and go
    ## through several layers of validation. Blocks that have gone through
    ## validations can be trusted to be well-formed, with a correct signature,
    ## having a parent and applying cleanly to the state that their parent
    ## left them with.
    ##
    ## When loading such blocks from the database, to rewind states for example,
    ## it is expensive to redo the validations (in particular, the signature
    ## checks), thus `TrustedBlock` uses a `TrustedSig` type to mark that these
    ## checks can be skipped.
    ##
    ## TODO this could probably be solved with some type trickery, but there
    ##      too many bugs in nim around generics handling, and we've used up
    ##      the trickery budget in the serialization library already. Until
    ##      then, the type must be manually kept compatible with its untrusted
    ##      cousin.
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest ##\
    state_root*: Eth2Digest ##\
    body*: TrustedBeaconBlockBody

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#beaconblockheader
  BeaconBlockHeader* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body_root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#signingdata
  SigningData* = object
    object_root*: Eth2Digest
    domain*: Domain

  GraffitiBytes* = distinct array[32, byte]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

  TrustedBeaconBlockBody* = object
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data
    graffiti*: GraffitiBytes

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]

  SomeSignedBeaconBlock* = SignedBeaconBlock | TrustedSignedBeaconBlock
  SomeBeaconBlock* = BeaconBlock | TrustedBeaconBlock
  SomeBeaconBlockBody* = BeaconBlockBody | TrustedBeaconBlockBody
  SomeAttestation* = Attestation | TrustedAttestation
  SomeIndexedAttestation* = IndexedAttestation | TrustedIndexedAttestation

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#beaconstate
  BeaconState* = object
    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader ##\
    ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## Needed to process attestations, older to newer

    state_roots*: HashArray[Limit SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    historical_roots*: HashList[Eth2Digest, Limit HISTORICAL_ROOTS_LIMIT]

    # Eth1
    eth1_data*: Eth1Data
    eth1_data_votes*:
      HashList[Eth1Data, Limit(EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)]
    eth1_deposit_index*: uint64

    # Registry
    validators*: HashList[Validator, Limit VALIDATOR_REGISTRY_LIMIT]
    balances*: HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

    # Randomness
    randao_mixes*: HashArray[Limit EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]

    # Slashings
    slashings*: HashArray[Limit EPOCHS_PER_SLASHINGS_VECTOR, uint64] ##\
    ## Per-epoch sums of slashed effective balances

    # Attestations
    previous_epoch_attestations*:
      HashList[PendingAttestation, Limit(MAX_ATTESTATIONS * SLOTS_PER_EPOCH)]
    current_epoch_attestations*:
      HashList[PendingAttestation, Limit(MAX_ATTESTATIONS * SLOTS_PER_EPOCH)]

    # Finality
    justification_bits*: uint8 ##\
    ## Bit set for every recent justified epoch
    ## Model a Bitvector[4] as a one-byte uint, which should remain consistent
    ## with ssz/hashing.

    previous_justified_checkpoint*: Checkpoint ##\
    ## Previous epoch snapshot

    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

  BeaconStateRef* = ref BeaconState

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#validator
  Validator* = object
    pubkey*: ValidatorPubKey

    withdrawal_credentials*: Eth2Digest ##\
    ## Commitment to pubkey for withdrawals and transfers

    effective_balance*: uint64 ##\
    ## Balance at stake

    slashed*: bool

    # Status epochs
    activation_eligibility_epoch*: Epoch ##\
    ## When criteria for activation were met

    activation_epoch*: Epoch
    exit_epoch*: Epoch

    withdrawable_epoch*: Epoch ##\
    ## When validator can withdraw or transfer funds

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#pendingattestation
  PendingAttestation* = object
    aggregation_bits*: CommitteeValidatorsBits
    data*: AttestationData

    # TODO this is a Slot
    inclusion_delay*: uint64

    proposer_index*: uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#historicalbatch
  HistoricalBatch* = object
    block_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    state_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#fork
  Fork* = object
    # TODO: Spec introduced an alias for Version = array[4, byte]
    #       and a default parameter to compute_domain
    previous_version*: Version
    current_version*: Version

    epoch*: Epoch ##\
    ## Epoch of latest fork

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#eth1data
  Eth1Data* = object
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    block_hash*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#eth1block
  Eth1Block* = object
    timestamp*: uint64
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    # All other eth1 block fields

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#signedvoluntaryexit
  SignedVoluntaryExit* = object
    message*: VoluntaryExit
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#signedbeaconblock
  SignedBeaconBlock* = object
    message*: BeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/beacon-chain.md#signedbeaconblockheader
  SignedBeaconBlockHeader* = object
    message*: BeaconBlockHeader
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#aggregateandproof
  AggregateAndProof* = object
    aggregator_index*: uint64
    aggregate*: Attestation
    selection_proof*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#signedaggregateandproof
  SignedAggregateAndProof* = object
    message*: AggregateAndProof
    signature*: ValidatorSig

  # TODO to be replaced with some magic hash caching
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  StateCache* = object
    shuffled_active_validator_indices*:
      Table[Epoch, seq[ValidatorIndex]]
    beacon_proposer_indices*: Table[Slot, Option[ValidatorIndex]]

func shortValidatorKey*(state: BeaconState, validatorIdx: int): string =
    ($state.validators[validatorIdx].pubkey)[0..7]

func getDepositMessage*(depositData: DepositData): DepositMessage =
  result.pubkey = depositData.pubkey
  result.amount = depositData.amount
  result.withdrawal_credentials = depositData.withdrawal_credentials

func getDepositMessage*(deposit: Deposit): DepositMessage =
  deposit.data.getDepositMessage

# TODO when https://github.com/nim-lang/Nim/issues/14440 lands in Status's Nim,
# switch proc {.noSideEffect.} to func.
template ethTimeUnit(typ: type) {.dirty.} =
  proc `+`*(x: typ, y: uint64): typ {.borrow, noSideEffect.}
  proc `-`*(x: typ, y: uint64): typ {.borrow, noSideEffect.}
  proc `-`*(x: uint64, y: typ): typ {.borrow, noSideEffect.}

  # Not closed over type in question (Slot or Epoch)
  proc `mod`*(x: typ, y: uint64): uint64 {.borrow, noSideEffect.}
  proc `div`*(x: typ, y: uint64): uint64 {.borrow, noSideEffect.}
  proc `div`*(x: uint64, y: typ): uint64 {.borrow, noSideEffect.}
  proc `-`*(x: typ, y: typ): uint64 {.borrow, noSideEffect.}

  proc `*`*(x: typ, y: uint64): uint64 {.borrow, noSideEffect.}

  proc `+=`*(x: var typ, y: typ) {.borrow, noSideEffect.}
  proc `+=`*(x: var typ, y: uint64) {.borrow, noSideEffect.}
  proc `-=`*(x: var typ, y: typ) {.borrow, noSideEffect.}
  proc `-=`*(x: var typ, y: uint64) {.borrow, noSideEffect.}

  # Comparison operators
  proc `<`*(x: typ, y: typ): bool {.borrow, noSideEffect.}
  proc `<`*(x: typ, y: uint64): bool {.borrow, noSideEffect.}
  proc `<`*(x: uint64, y: typ): bool {.borrow, noSideEffect.}
  proc `<=`*(x: typ, y: typ): bool {.borrow, noSideEffect.}
  proc `<=`*(x: typ, y: uint64): bool {.borrow, noSideEffect.}
  proc `<=`*(x: uint64, y: typ): bool {.borrow, noSideEffect.}

  proc `==`*(x: typ, y: typ): bool {.borrow, noSideEffect.}
  proc `==`*(x: typ, y: uint64): bool {.borrow, noSideEffect.}
  proc `==`*(x: uint64, y: typ): bool {.borrow, noSideEffect.}

  # Nim integration
  proc `$`*(x: typ): string {.borrow, noSideEffect.}
  proc hash*(x: typ): Hash {.borrow, noSideEffect.}
  proc `%`*(x: typ): JsonNode {.borrow, noSideEffect.}

  # Serialization
  proc writeValue*(writer: var JsonWriter, value: typ)
                  {.raises: [IOError, Defect].}=
    writeValue(writer, uint64 value)

  proc readValue*(reader: var JsonReader, value: var typ)
                 {.raises: [IOError, SerializationError, Defect].} =
    value = typ reader.readValue(uint64)

proc writeValue*(writer: var JsonWriter, value: ValidatorIndex)
                {.raises: [IOError, Defect].} =
  writeValue(writer, uint32 value)

proc readValue*(reader: var JsonReader, value: var ValidatorIndex)
               {.raises: [IOError, SerializationError, Defect].} =
  value = ValidatorIndex reader.readValue(uint32)

template writeValue*(writer: var JsonWriter, value: Version | ForkDigest) =
  writeValue(writer, $value)

proc readValue*(reader: var JsonReader, value: var Version)
               {.raises: [IOError, SerializationError, Defect].} =
  let hex = reader.readValue(string)
  try:
    hexToByteArray(hex, array[4, byte](value))
  except ValueError:
    raiseUnexpectedValue(reader, "Hex string of 4 bytes expected")

proc readValue*(reader: var JsonReader, value: var ForkDigest)
               {.raises: [IOError, SerializationError, Defect].} =
  let hex = reader.readValue(string)
  try:
    hexToByteArray(hex, array[4, byte](value))
  except ValueError:
    raiseUnexpectedValue(reader, "Hex string of 4 bytes expected")

# `ValidatorIndex` seq handling.
# TODO harden these against uint32/uint64 to int type conversion risks
func max*(a: ValidatorIndex, b: int) : auto =
  max(a.int, b)

func `[]`*[T](a: var seq[T], b: ValidatorIndex): var T =
  a[b.int]

func `[]`*[T](a: seq[T], b: ValidatorIndex): auto =
  a[b.int]

func `[]=`*[T](a: var seq[T], b: ValidatorIndex, c: T) =
  a[b.int] = c

# `ValidatorIndex` Nim integration
proc `==`*(x, y: ValidatorIndex) : bool {.borrow, noSideEffect.}
proc `<`*(x, y: ValidatorIndex) : bool {.borrow, noSideEffect.}
proc hash*(x: ValidatorIndex): Hash {.borrow, noSideEffect.}
func `$`*(x: ValidatorIndex): auto = $(x.int64)

func `as`*(d: DepositData, T: type DepositMessage): T =
  T(pubkey: d.pubkey,
    withdrawal_credentials: d.withdrawal_credentials,
    amount: d.amount)

ethTimeUnit Slot
ethTimeUnit Epoch

Json.useCustomSerialization(BeaconState.justification_bits):
  read:
    let s = reader.readValue(string)

    if s.len != 4:
      raiseUnexpectedValue(reader, "A string with 4 characters expected")

    try:
      s.parseHexInt.uint8
    except ValueError:
      raiseUnexpectedValue(reader, "The `justification_bits` value must be a hex string")

  write:
    writer.writeValue "0x" & value.toHex

Json.useCustomSerialization(BitSeq):
  read:
    try:
      BitSeq reader.readValue(string).hexToSeqByte
    except ValueError:
      raiseUnexpectedValue(reader, "A BitSeq value should be a valid hex string")

  write:
    writer.writeValue "0x" & seq[byte](value).toHex

template readValue*(reader: var JsonReader, value: var List) =
  value = type(value)(readValue(reader, seq[type value[0]]))

template writeValue*(writer: var JsonWriter, value: List) =
  writeValue(writer, asSeq value)

template readValue*(reader: var JsonReader, value: var BitList) =
  type T = type(value)
  value = T readValue(reader, BitSeq)

template writeValue*(writer: var JsonWriter, value: BitList) =
  writeValue(writer, BitSeq value)

template newClone*[T: not ref](x: T): ref T =
  # TODO not nil in return type: https://github.com/nim-lang/Nim/issues/14146
  # TODO use only when x is a function call that returns a new instance!
  let res = new typeof(x) # TODO safe to do noinit here?
  res[] = x
  res

template assignClone*[T: not ref](x: T): ref T =
  # This is a bit of a mess: if x is an rvalue (temporary), RVO kicks in for
  # newClone - if it's not, `genericAssign` will be called which is ridiculously
  # slow - so `assignClone` should be used when RVO doesn't work. sigh.
  let res = new typeof(x) # TODO safe to do noinit here?
  assign(res[], x)
  res

template newClone*[T](x: ref T): ref T =
  if x.isNil:
    nil
  else:
    newClone(x[])

template lenu64*(x: untyped): untyped =
  x.len.uint64

func `$`*(v: ForkDigest | Version): string =
  toHex(array[4, byte](v))

# TODO where's borrow support when you need it
func `==`*(a, b: ForkDigest | Version): bool =
  array[4, byte](a) == array[4, byte](b)
func len*(v: ForkDigest | Version): int = sizeof(v)
func low*(v: ForkDigest | Version): int = 0
func high*(v: ForkDigest | Version): int = len(v) - 1
func `[]`*(v: ForkDigest | Version, idx: int): byte = array[4, byte](v)[idx]

func shortLog*(s: Slot): uint64 =
  s - GENESIS_SLOT

func shortLog*(e: Epoch): uint64 =
  e - GENESIS_EPOCH

func shortLog*(v: SomeBeaconBlock): auto =
  (
    slot: shortLog(v.slot),
    proposer_index: v.proposer_index,
    parent_root: shortLog(v.parent_root),
    state_root: shortLog(v.state_root),
    proposer_slashings_len: v.body.proposer_slashings.len(),
    attester_slashings_len: v.body.attester_slashings.len(),
    attestations_len: v.body.attestations.len(),
    deposits_len: v.body.deposits.len(),
    voluntary_exits_len: v.body.voluntary_exits.len(),
  )

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func shortLog*(v: DepositData): auto =
  (
    pubkey: shortLog(v.pubkey),
    withdrawal_credentials: shortlog(v.withdrawal_credentials),
    amount: v.amount,
    signature: shortLog(v.signature)
  )

func shortLog*(v: Checkpoint): auto =
  (
    epoch: shortLog(v.epoch),
    root: shortLog(v.root),
  )

func shortLog*(v: AttestationData): auto =
  (
    slot: shortLog(v.slot),
    index: v.index,
    beacon_block_root: shortLog(v.beacon_block_root),
    source: shortLog(v.source),
    target: shortLog(v.target),
  )

func shortLog*(v: PendingAttestation): auto =
  (
    aggregation_bits: v.aggregation_bits,
    data: shortLog(v.data),
    inclusion_delay: v.inclusion_delay,
    proposer_index: v.proposer_index
  )

func shortLog*(v: SomeAttestation): auto =
  (
    aggregation_bits: v.aggregation_bits,
    data: shortLog(v.data),
    signature: shortLog(v.signature)
  )

chronicles.formatIt Slot: it.shortLog
chronicles.formatIt Epoch: it.shortLog
chronicles.formatIt BeaconBlock: it.shortLog
chronicles.formatIt AttestationData: it.shortLog
chronicles.formatIt Attestation: it.shortLog
chronicles.formatIt Checkpoint: it.shortLog

import json_serialization
export json_serialization
export writeValue, readValue

const
  # http://facweb.cs.depaul.edu/sjost/it212/documents/ascii-pr.htm
  PrintableAsciiChars = {'!'..'~'}

func `$`*(value: GraffitiBytes): string =
  result = strip(string.fromBytes(distinctBase value),
                 leading = false,
                 chars = Whitespace + {'\0'})

  # TODO: Perhaps handle UTF-8 at some point
  if not allCharsInSet(result, PrintableAsciiChars):
    result = "0x" & toHex(distinctBase value)

func init*(T: type GraffitiBytes, input: string): GraffitiBytes
          {.raises: [ValueError, Defect].} =
  if input.len > 2 and input[0] == '0' and input[1] == 'x':
    if input.len > sizeof(GraffitiBytes) * 2 + 2:
      raise newException(ValueError, "The graffiti bytes should be less than 32")
    elif input.len mod 2 != 0:
      raise newException(ValueError, "The graffiti hex string should have an even length")

    hexToByteArray(string input, distinctBase(result))
  else:
    if input.len > 32:
      raise newException(ValueError, "The graffiti value should be 32 characters or less")
    distinctBase(result)[0 ..< input.len] = toBytes(input)

func defaultGraffitiBytes*(): GraffitiBytes =
  let graffitiBytes = toBytes("Nimbus " & fullVersionStr)
  distinctBase(result)[0 ..< graffitiBytes.len] = graffitiBytes

proc writeValue*(w: var JsonWriter, value: GraffitiBytes)
                {.raises: [IOError, Defect].} =
  w.writeValue $value

template `==`*(lhs, rhs: GraffitiBytes): bool =
  distinctBase(lhs) == distinctBase(rhs)

proc readValue*(r: var JsonReader, T: type GraffitiBytes): T
               {.raises: [IOError, SerializationError, Defect].} =
  try:
    init(GraffitiBytes, r.readValue(string))
  except ValueError as err:
    r.raiseUnexpectedValue err.msg

static:
  # Sanity checks - these types should be trivial enough to copy with memcpy
  doAssert supportsCopyMem(Validator)
  doAssert supportsCopyMem(Eth2Digest)

func assign*[T](tgt: var T, src: T) =
  # The default `genericAssignAux` that gets generated for assignments in nim
  # is ridiculously slow. When syncing, the application was spending 50%+ CPU
  # time in it - `assign`, in the same test, doesn't even show in the perf trace

  when supportsCopyMem(T):
    when sizeof(src) <= sizeof(int):
      tgt = src
    else:
      copyMem(addr tgt, unsafeAddr src, sizeof(tgt))
  elif T is object|tuple:
    for t, s in fields(tgt, src):
      when supportsCopyMem(type s) and sizeof(s) <= sizeof(int) * 2:
        t = s # Shortcut
      else:
        assign(t, s)
  elif T is List|BitList:
    assign(distinctBase tgt, distinctBase src)
  elif T is seq:
    tgt.setLen(src.len)
    when supportsCopyMem(type(tgt[0])):
      if tgt.len > 0:
        copyMem(addr tgt[0], unsafeAddr src[0], sizeof(tgt[0]) * tgt.len)
    else:
      for i in 0..<tgt.len:
        assign(tgt[i], src[i])
  elif T is ref:
    tgt = src
  else:
    unsupported T
