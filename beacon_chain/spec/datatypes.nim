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

# TODO report compiler crash when this is uncommented
# {.push raises: [Defect].}

{.experimental: "notnil".}

{.push raises: [Defect].}

import
  macros, hashes, json, strutils, tables,
  stew/[byteutils], chronicles,
  json_serialization/types as jsonTypes,
  ../ssz/types as sszTypes, ./crypto, ./digest

export
  sszTypes

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


# Constant presets
const const_preset* {.strdefine.} = "mainnet"

when const_preset == "mainnet":
  import ./presets/mainnet
  export mainnet
elif const_preset == "minimal":
  import ./presets/minimal
  export minimal
else:
  type
    Slot* = distinct uint64
    Epoch* = distinct uint64

  import ./presets/custom
  loadCustomPreset const_preset

const
  SPEC_VERSION* = "0.11.3" ## \
  ## Spec version we're aiming to be compatible with, right now

  GENESIS_SLOT* = Slot(0)
  GENESIS_EPOCH* = (GENESIS_SLOT.int div SLOTS_PER_EPOCH).Epoch ##\
  ## compute_epoch_at_slot(GENESIS_SLOT)

  FAR_FUTURE_EPOCH* = (not 0'u64).Epoch # 2^64 - 1 in spec

  # Not part of spec. Still useful, pending removing usage if appropriate.
  ZERO_HASH* = Eth2Digest()

  # Not part of spec
  WEAK_SUBJECTVITY_PERIOD* =
    Slot(uint64(4 * 30 * 24 * 60 * 60) div SECONDS_PER_SLOT)
    # TODO: This needs revisiting.
    # Why was the validator WITHDRAWAL_PERIOD altered in the spec?

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.2/specs/phase0/p2p-interface.md#configuration
  ATTESTATION_PROPAGATION_SLOT_RANGE* = 32

  SLOTS_PER_ETH1_VOTING_PERIOD* = Slot(EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH)

  DEPOSIT_CONTRACT_TREE_DEPTH* = 32
  BASE_REWARDS_PER_EPOCH* = 4

template maxSize*(n: int) {.pragma.}

type
  # Domains
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#domain-types
  DomainType* = enum
    DOMAIN_BEACON_PROPOSER = 0
    DOMAIN_BEACON_ATTESTER = 1
    DOMAIN_RANDAO = 2
    DOMAIN_DEPOSIT = 3
    DOMAIN_VOLUNTARY_EXIT = 4
    DOMAIN_SELECTION_PROOF = 5
    DOMAIN_AGGREGATE_AND_PROOF = 6
    # Phase 1 - Sharding
    # https://github.com/ethereum/eth2.0-specs/blob/v0.11.2/specs/phase1/beacon-chain.md#misc
    DOMAIN_SHARD_PROPOSAL = 128
    DOMAIN_SHARD_COMMITTEE = 129
    DOMAIN_LIGHT_CLIENT = 130
    # Phase 1 - Custody game
    # https://github.com/ethereum/eth2.0-specs/blob/v0.11.2/specs/phase1/custody-game.md#signature-domain-types
    DOMAIN_CUSTODY_BIT_SLASHING = 0x83

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#custom-types
  Domain* = array[32, byte]

  # https://github.com/nim-lang/Nim/issues/574 and be consistent across
  # 32-bit and 64-bit word platforms.
  # TODO VALIDATOR_REGISTRY_LIMIT is 1 shl 40 in 0.8.3, and
  # proc newSeq(typ: PNimType, len: int): pointer {.compilerRtl.}
  # in Nim/lib/system/gc.nim quite tightly ties seq addressibility
  # to the system wordsize. This lifts smaller, and now incorrect,
  # range-limit.
  ValidatorIndex* = distinct uint32
  Gwei* = uint64
  CommitteeIndex* = distinct uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#proposerslashing
  ProposerSlashing* = object
    signed_header_1*: SignedBeaconBlockHeader
    signed_header_2*: SignedBeaconBlockHeader

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#attesterslashing
  AttesterSlashing* = object
    attestation_1*: IndexedAttestation
    attestation_2*: IndexedAttestation

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#indexedattestation
  IndexedAttestation* = object
    # TODO ValidatorIndex, but that doesn't serialize properly
    attesting_indices*: List[uint64, MAX_VALIDATORS_PER_COMMITTEE]
    data*: AttestationData
    signature*: ValidatorSig

  CommitteeValidatorsBits* = BitList[MAX_VALIDATORS_PER_COMMITTEE]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#attestation
  Attestation* = object
    aggregation_bits*: CommitteeValidatorsBits
    data*: AttestationData
    signature*: ValidatorSig

  Version* = distinct array[4, byte]
  ForkDigest* = distinct array[4, byte]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#forkdata
  ForkData* = object
    current_version*: Version
    genesis_validators_root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#checkpoint
  Checkpoint* = object
    epoch*: Epoch
    root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#AttestationData
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#deposit
  Deposit* = object
    proof*: array[DEPOSIT_CONTRACT_TREE_DEPTH + 1, Eth2Digest] ##\
    ## Merkle path to deposit root

    data*: DepositData

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#depositmessage
  DepositMessage* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: Gwei

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#depositdata
  DepositData* = object
    pubkey*: ValidatorPubKey
    withdrawal_credentials*: Eth2Digest
    amount*: uint64
    signature*: ValidatorSig  # Signing over DepositMessage

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#voluntaryexit
  VoluntaryExit* = object
    epoch*: Epoch ##\
    ## Earliest epoch when voluntary exit can be processed

    validator_index*: uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#beaconblock
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#beaconblockheader
  BeaconBlockHeader* = object
    slot*: Slot
    proposer_index*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body_root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    graffiti*: Eth2Digest # TODO make that raw bytes

    # Operations
    proposer_slashings*: List[ProposerSlashing, MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, MAX_ATTESTATIONS]
    deposits*: List[Deposit, MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, MAX_VOLUNTARY_EXITS]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#beaconstate
  BeaconStateObj* = object
    # Versioning
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader ##\
    ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: HashArray[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## Needed to process attestations, older to newer

    state_roots*: HashArray[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    historical_roots*: HashList[Eth2Digest, HISTORICAL_ROOTS_LIMIT]

    # Eth1
    eth1_data*: Eth1Data
    eth1_data_votes*:
      HashList[Eth1Data, EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH]
    eth1_deposit_index*: uint64

    # Registry
    validators*: HashList[Validator, VALIDATOR_REGISTRY_LIMIT]
    balances*: HashList[uint64, VALIDATOR_REGISTRY_LIMIT]

    # Randomness
    randao_mixes*: HashArray[EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]

    # Slashings
    slashings*: HashArray[int64(EPOCHS_PER_SLASHINGS_VECTOR), uint64] ##\
    ## Per-epoch sums of slashed effective balances

    # Attestations
    previous_epoch_attestations*:
      HashList[PendingAttestation, MAX_ATTESTATIONS * SLOTS_PER_EPOCH]
    current_epoch_attestations*:
      HashList[PendingAttestation, MAX_ATTESTATIONS * SLOTS_PER_EPOCH]

    # Finality
    justification_bits*: uint8 ##\
    ## Bit set for every recent justified epoch
    ## Model a Bitvector[4] as a one-byte uint, which should remain consistent
    ## with ssz/hashing.

    previous_justified_checkpoint*: Checkpoint ##\
    ## Previous epoch snapshot

    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

  BeaconState* = BeaconStateObj
  BeaconStateRef* = ref BeaconStateObj not nil
  NilableBeaconStateRef* = ref BeaconStateObj

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#validator
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#pendingattestation
  PendingAttestation* = object
    aggregation_bits*: CommitteeValidatorsBits
    data*: AttestationData

    # TODO this is a Slot
    inclusion_delay*: uint64

    proposer_index*: uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#historicalbatch
  HistoricalBatch* = object
    block_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    state_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#fork
  Fork* = object
    # TODO: Spec introduced an alias for Version = array[4, byte]
    #       and a default parameter to compute_domain
    previous_version*: Version
    current_version*: Version

    epoch*: Epoch ##\
    ## Epoch of latest fork

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#eth1data
  Eth1Data* = object
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    block_hash*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#signingroot
  SigningRoot* = object
    object_root*: Eth2Digest
    domain*: Domain

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#signedvoluntaryexit
  SignedVoluntaryExit* = object
    message*: VoluntaryExit
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#signedbeaconblock
  SignedBeaconBlock* = object
    message*: BeaconBlock
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.3/specs/phase0/beacon-chain.md#signedbeaconblockheader
  SignedBeaconBlockHeader* = object
    message*: BeaconBlockHeader
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.2/specs/phase0/validator.md#aggregateandproof
  AggregateAndProof* = object
    aggregator_index*: uint64
    aggregate*: Attestation
    selection_proof*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.2/specs/phase0/validator.md#signedaggregateandproof
  SignedAggregateAndProof* = object
    message*: AggregateAndProof
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.2/specs/phase0/validator.md#eth1block
  Eth1Block* = object
    timestamp*: uint64
    # All other eth1 block fields

  # TODO to be replaced with some magic hash caching
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  StateCache* = object
    shuffled_active_validator_indices*:
      Table[Epoch, seq[ValidatorIndex]]
    committee_count_cache*: Table[Epoch, uint64]
    beacon_proposer_indices*: Table[Slot, Option[ValidatorIndex]]

  JsonError = jsonTypes.JsonError

func shortValidatorKey*(state: BeaconState, validatorIdx: int): string =
    ($state.validators[validatorIdx].pubkey)[0..7]

func getDepositMessage*(depositData: DepositData): DepositMessage =
  result.pubkey = depositData.pubkey
  result.amount = depositData.amount
  result.withdrawal_credentials = depositData.withdrawal_credentials

func getDepositMessage*(deposit: Deposit): DepositMessage =
  deposit.data.getDepositMessage

template ethTimeUnit(typ: type) {.dirty.} =
  proc `+`*(x: typ, y: uint64): typ {.borrow.}
  proc `-`*(x: typ, y: uint64): typ {.borrow.}
  proc `-`*(x: uint64, y: typ): typ {.borrow.}

  # Not closed over type in question (Slot or Epoch)
  proc `mod`*(x: typ, y: uint64): uint64 {.borrow.}
  proc `div`*(x: typ, y: uint64): uint64 {.borrow.}
  proc `div`*(x: uint64, y: typ): uint64 {.borrow.}
  proc `-`*(x: typ, y: typ): uint64 {.borrow.}

  proc `*`*(x: typ, y: uint64): uint64 {.borrow.}

  proc `+=`*(x: var typ, y: typ) {.borrow.}
  proc `+=`*(x: var typ, y: uint64) {.borrow.}
  proc `-=`*(x: var typ, y: typ) {.borrow.}
  proc `-=`*(x: var typ, y: uint64) {.borrow.}

  # Comparison operators
  proc `<`*(x: typ, y: typ): bool {.borrow.}
  proc `<`*(x: typ, y: uint64): bool {.borrow.}
  proc `<`*(x: uint64, y: typ): bool {.borrow.}
  proc `<=`*(x: typ, y: typ): bool {.borrow.}
  proc `<=`*(x: typ, y: uint64): bool {.borrow.}
  proc `<=`*(x: uint64, y: typ): bool {.borrow.}

  proc `==`*(x: typ, y: typ): bool {.borrow.}
  proc `==`*(x: typ, y: uint64): bool {.borrow.}
  proc `==`*(x: uint64, y: typ): bool {.borrow.}

  # Nim integration
  proc `$`*(x: typ): string {.borrow.}
  proc hash*(x: typ): Hash {.borrow.}
  proc `%`*(x: typ): JsonNode {.borrow.}

  # Serialization
  proc writeValue*(writer: var JsonWriter, value: typ)
                  {.raises: [IOError, Defect].}=
    writeValue(writer, uint64 value)

  proc readValue*(reader: var JsonReader, value: var typ)
                 {.raises: [IOError, JsonError, Defect].} =
    value = typ reader.readValue(uint64)

proc writeValue*(writer: var JsonWriter, value: ValidatorIndex)
                {.raises: [IOError, Defect].} =
  writeValue(writer, uint32 value)

proc readValue*(reader: var JsonReader, value: var ValidatorIndex)
               {.raises: [IOError, JsonError, Defect].} =
  value = ValidatorIndex reader.readValue(uint32)

template writeValue*(writer: var JsonWriter, value: Version | ForkDigest) =
  writeValue(writer, $value)

proc readValue*(reader: var JsonReader, value: var Version)
               {.raises: [IOError, JsonError, Defect].} =
  let hex = reader.readValue(string)
  try:
    hexToByteArray(hex, array[4, byte](value))
  except ValueError:
    raiseUnexpectedValue(reader, "Hex string of 4 bytes expected")

proc readValue*(reader: var JsonReader, value: var ForkDigest)
               {.raises: [IOError, JsonError, Defect].} =
  let hex = reader.readValue(string)
  try:
    hexToByteArray(hex, array[4, byte](value))
  except ValueError:
    raiseUnexpectedValue(reader, "Hex string of 4 bytes expected")

# `ValidatorIndex` seq handling.
proc max*(a: ValidatorIndex, b: int) : auto =
  max(a.int, b)

proc `[]`*[T](a: var seq[T], b: ValidatorIndex): var T =
  a[b.int]

proc `[]`*[T](a: seq[T], b: ValidatorIndex): auto =
  a[b.int]

proc `[]=`*[T](a: var seq[T], b: ValidatorIndex, c: T) =
  a[b.int] = c

# `ValidatorIndex` Nim integration
proc `==`*(x, y: ValidatorIndex) : bool {.borrow.}
proc `<`*(x, y: ValidatorIndex) : bool {.borrow.}
proc hash*(x: ValidatorIndex): Hash {.borrow.}
proc `$`*(x: ValidatorIndex): auto = $(x.int64)

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
  let res = new typeof(x) # TODO safe to do noinit here?
  res[] = x
  res

template newClone*[T](x: ref T not nil): ref T =
  newClone(x[])

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

func shortLog*(v: BeaconBlock): auto =
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

func shortLog*(v: SignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

func shortLog*(v: AttestationData): auto =
  (
    slot: shortLog(v.slot),
    index: v.index,
    beacon_block_root: shortLog(v.beacon_block_root),
    source_epoch: shortLog(v.source.epoch),
    source_root: shortLog(v.source.root),
    target_epoch: shortLog(v.target.epoch),
    target_root: shortLog(v.target.root)
  )

func shortLog*(v: Attestation): auto =
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

import json_serialization
export json_serialization
export writeValue, readValue
