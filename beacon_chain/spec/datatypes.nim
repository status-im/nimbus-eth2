# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
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

import
  macros, hashes, math, json, strutils,
  stew/[byteutils, bitseqs], chronicles, eth/[common, rlp],
  ../ssz/types, ./crypto, ./digest

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
# https://github.com/ethereum/eth2.0-specs/tree/v0.6.3/configs/constant_presets/
const const_preset* {.strdefine.} = "minimal"

when const_preset == "mainnet":
  import ./presets/mainnet
  export mainnet
elif const_preset == "minimal":
  import ./presets/minimal
  export minimal
else:
  {.fatal: "Preset \"" & const_preset ".nim\" is not supported.".}

const
  SPEC_VERSION* = "0.8.1" ## \
  ## Spec version we're aiming to be compatible with, right now
  ## TODO: improve this scheme once we can negotiate versions in protocol

  # Initial values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#initial-values
  GENESIS_EPOCH* = (GENESIS_SLOT.uint64 div SLOTS_PER_EPOCH).Epoch ##\
  ## compute_epoch_of_slot(GENESIS_SLOT)

  FAR_FUTURE_EPOCH* = (not 0'u64).Epoch # 2^64 - 1 in spec

  # Not part of spec. Still useful, pending removing usage if appropriate.
  ZERO_HASH* = Eth2Digest()

template maxSize*(n: int) {.pragma.}

type
  ValidatorIndex* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around
  Shard* = uint64
  Gwei* = uint64
  Domain* = uint64

  BitList*[maxLen: static int] = distinct BitSeq

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#proposerslashing
  ProposerSlashing* = object
    proposer_index*: uint64 ##\
    ## Proposer index

    header_1*: BeaconBlockHeader ##\
    # First block header

    header_2*: BeaconBlockHeader ##\
    # Second block header

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#attesterslashing
  AttesterSlashing* = object
    attestation_1*: IndexedAttestation ## \
    ## First attestation
    attestation_2*: IndexedAttestation ## \
    ## Second attestation

  CustodyBitIndices* = List[uint64, MAX_VALIDATORS_PER_COMMITTEE]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#indexedattestation
  IndexedAttestation* = object
    # These probably should be seq[ValidatorIndex], but that throws RLP errors
    custody_bit_0_indices*: CustodyBitIndices
    custody_bit_1_indices*: CustodyBitIndices

    data*: AttestationData ## \
    ## Attestation data

    signature*: ValidatorSig ## \
    ## Aggregate signature

  CommitteeValidatorsBits* = BitList[MAX_VALIDATORS_PER_COMMITTEE]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#attestation
  Attestation* = object
    aggregation_bits*: CommitteeValidatorsBits ##\
    ## Attester aggregation bitfield

    data*: AttestationData ##\
    ## Attestation data

    custody_bits*: CommitteeValidatorsBits ##\
    ## Custody bitfield

    signature*: ValidatorSig ##\
    ## BLS aggregate signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#checkpoint
  Checkpoint* = object
    epoch*: Epoch
    root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#AttestationData
  AttestationData* = object
    # LMD GHOST vote
    beacon_block_root*: Eth2Digest

    # FFG vote
    source*: Checkpoint
    target*: Checkpoint

    # Crosslink vote
    crosslink*: Crosslink

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#attestationdataandcustodybit
  AttestationDataAndCustodyBit* = object
    data*: AttestationData

    custody_bit*: bool ##\
    ## Challengeable bit (SSZ-bool, 1 byte) for the custody of crosslink data

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#deposit
  Deposit* = object
    proof*: array[DEPOSIT_CONTRACT_TREE_DEPTH + 1, Eth2Digest] ##\
    ## Merkle path to deposit data list root

    data*: DepositData

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#depositdata
  DepositData* = object
    pubkey*: ValidatorPubKey ##\
    ## BLS pubkey

    withdrawal_credentials*: Eth2Digest ##\
    ## Withdrawal credentials

    amount*: uint64 ##\
    ## Amount in Gwei

    signature*: ValidatorSig ##\
    ## Container self-signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#voluntaryexit
  VoluntaryExit* = object
    epoch*: Epoch ##\
    ## Earliest epoch when voluntary exit can be processed

    validator_index*: uint64
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#transfer
  Transfer* = object
    sender*: uint64 ##\
    ## Sender index

    recipient*: uint64 ##\
    ## Recipient index

    # TODO amount and fee are Gwei-typed
    amount*: uint64 ##\
    ## Amount in Gwei

    fee*: uint64 ##\
    ## Fee in Gwei for block proposer

    slot*: Slot ##\
    ## Slot at which transfer must be processed

    pubkey*: ValidatorPubKey ##\
    ## Withdrawal pubkey

    signature*: ValidatorSig ##\
    ## Signature checked against withdrawal pubkey

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot

    parent_root*: Eth2Digest ##\
    ## Root hash of the previous block

    state_root*: Eth2Digest ##\
    ## The state root, _after_ this block has been processed

    body*: BeaconBlockBody

    signature*: ValidatorSig ##\
    ## Proposer signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#compactcommittee
  CompactCommittee* = object
    pubkeys*: seq[ValidatorPubKey]
    compact_validators*: seq[uint64]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#beaconblockheader
  BeaconBlockHeader* = object
    slot*: Slot
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body_root*: Eth2Digest
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    graffiti*: Eth2Digest
    proposer_slashings*: seq[ProposerSlashing]
    attester_slashings*: seq[AttesterSlashing]
    attestations*: seq[Attestation]
    deposits*: seq[Deposit]
    voluntary_exits*: seq[VoluntaryExit]
    transfers*: seq[Transfer]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#beaconstate
  BeaconState* = object
    # Versioning
    genesis_time*: uint64
    slot*: Slot
    fork*: Fork

    # History
    latest_block_header*: BeaconBlockHeader ##\
    ## `latest_block_header.state_root == ZERO_HASH` temporarily

    block_roots*: array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## Needed to process attestations, older to newer

    state_roots*: array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]

    historical_roots*: seq[Eth2Digest]  ##\
    ## model List with HISTORICAL_ROOTS_LIMIT limit as seq
    ## TODO bound explicitly somewhere

    # Eth1
    eth1_data*: Eth1Data

    eth1_data_votes*: seq[Eth1Data] ##\
    ## As with `hitorical_roots`, this is a `List`. TODO bound explicitly.

    eth1_deposit_index*: uint64

    # Registry
    validators*: seq[Validator]
    balances*: seq[uint64] ##\
    ## Validator balances in Gwei!
    ## Also more `List`s which need to be bounded explicitly at
    ## VALIDATOR_REGISTRY_LIMIT

    # Shuffling
    start_shard*: Shard
    randao_mixes*: array[EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest]

    active_index_roots*: array[EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest] ##\
    ## Active index digests for light clients

    compact_committees_roots*: array[EPOCHS_PER_HISTORICAL_VECTOR, Eth2Digest] ##\
    ## Committee digests for light clients

    # Slashings
    slashings*: array[EPOCHS_PER_SLASHINGS_VECTOR, uint64] ##\
    ## Per-epoch sums of slashed effective balances

    # Attestations
    previous_epoch_attestations*: seq[PendingAttestation]
    current_epoch_attestations*: seq[PendingAttestation]

    # Crosslinks
    previous_crosslinks*: array[SHARD_COUNT, Crosslink]
    current_crosslinks*: array[SHARD_COUNT, Crosslink]

    # Finality
    justification_bits*: uint8 ##\
    ## Bit set for every recent justified epoch
    ## Model a Bitvector[4] as a one-byte uint, which should remain consistent
    ## with ssz/hashing.

    previous_justified_checkpoint*: Checkpoint ##\
    ## Previous epoch snapshot

    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#validator
  Validator* = object
    pubkey*: ValidatorPubKey

    withdrawal_credentials*: Eth2Digest ##\
    ## Commitment to pubkey for withdrawals and transfers

    effective_balance*: uint64 ##\
    ## Balance at stake

    slashed*: bool ##\
    ## Was the validator slashed

    # Status epochs
    activation_eligibility_epoch*: Epoch ##\
    ## When criteria for activation were met

    activation_epoch*: Epoch
    exit_epoch*: Epoch

    withdrawable_epoch*: Epoch ##\
    ## When validator can withdraw or transfer funds

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#crosslink
  Crosslink* = object
    shard*: Shard
    parent_root*: Eth2Digest

    start_epoch*: Epoch
    end_epoch*: Epoch ##\
    ## Crosslinking data

    data_root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.7.1/specs/core/0_beacon-chain.md#pendingattestation
  PendingAttestation* = object
    aggregation_bits*: CommitteeValidatorsBits ## Attester participation bitfield
    data*: AttestationData                     ## Attestation data
    inclusion_delay*: uint64                   ## Inclusion delay
    proposer_index*: uint64                    ## Proposer index

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#historicalbatch
  HistoricalBatch* = object
    block_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    state_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#fork
  Fork* = object
    previous_version*: array[4, byte]
    current_version*: array[4, byte]

    epoch*: Epoch ##\
    ## Epoch of latest fork

  # https://github.com/ethereum/eth2.0-specs/blob/v0.8.2/specs/core/0_beacon-chain.md#eth1data
  Eth1Data* = object
    deposit_root*: Eth2Digest ##\
    ## Root of the deposit tree

    deposit_count*: uint64 ##\
    ## Total number of deposits

    block_hash*: Eth2Digest ##\
    ## Block hash

  # TODO to be replaced with some magic hash caching
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root (not signing_root!)

template foreachSpecType*(op: untyped) =
  ## These are all spec types that will appear in network messages
  ## and persistent consensus data. This helper template is useful
  ## for populating RTTI tables that concern them.
  op Attestation
  op AttestationData
  op AttestationDataAndCustodyBit
  op AttesterSlashing
  op BeaconBlock
  op BeaconBlockBody
  op BeaconBlockHeader
  op BeaconState
  op Crosslink
  op Deposit
  op DepositData
  op Eth1Data
  op Fork
  op HistoricalBatch
  op IndexedAttestation
  op PendingAttestation
  op ProposerSlashing
  op Transfer
  op Validator
  op VoluntaryExit

macro fieldMaxLen*(x: typed): untyped =
  # TODO This macro is a temporary solution for the lack of a
  # more proper way to specify the max length of the List[T; N]
  # objects in the spec.
  # May be replaced with `getCustomPragma` once we upgrade to
  # Nim 0.20.2 or with a distinct List type, which would require
  # more substantial refactorings in the spec code.
  if x.kind != nnkDotExpr:
    return newLit(0)

  let size = case $x[1]
             of "pubkeys",
                "compact_validators",
                "custody_bit_0_indices",
                "custody_bit_1_indices",
                "aggregation_bits",
                "custody_bits": int64(MAX_VALIDATORS_PER_COMMITTEE)
             of "proposer_slashings": MAX_PROPOSER_SLASHINGS
             of "attester_slashings": MAX_ATTESTER_SLASHINGS
             of "attestations": MAX_ATTESTATIONS
             of "deposits": MAX_DEPOSITS
             of "voluntary_exits": MAX_VOLUNTARY_EXITS
             of "transfers": MAX_TRANSFERS
             of "historical_roots": HISTORICAL_ROOTS_LIMIT
             of "eth1_data_votes": SLOTS_PER_ETH1_VOTING_PERIOD
             of "validators": VALIDATOR_REGISTRY_LIMIT
             of "balances": VALIDATOR_REGISTRY_LIMIT
             of "previous_epoch_attestations",
                "current_epoch_attestations": MAX_ATTESTATIONS *
                                              SLOTS_PER_EPOCH
             else: 0

  newLit size

func shortValidatorKey*(state: BeaconState, validatorIdx: int): string =
    ($state.validators[validatorIdx].pubkey)[0..7]

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
  proc read*(rlp: var Rlp, T: type typ): typ {.inline.} =
    typ(rlp.read(uint64))

  proc append*(writer: var RlpWriter, value: typ) =
    writer.append uint64(value)

  proc writeValue*(writer: var JsonWriter, value: typ) =
    writeValue(writer, uint64 value)

  proc readValue*(reader: var JsonReader, value: var typ) =
    value = typ reader.readValue(uint64)

proc `%`*(i: uint64): JsonNode =
  % int(i)

ethTimeUnit Slot
ethTimeUnit Epoch

Json.useCustomSerialization(BeaconState.justification_bits):
  read:
    let s = reader.readValue(string)
    if s.len != 4: raise newException(ValueError, "unexpected number of bytes")
    s.parseHexInt.uint8

  write:
    writer.writeValue "0x" & value.toHex

Json.useCustomSerialization(BitSeq):
  read:
    BitSeq reader.readValue(string).hexToSeqByte

  write:
    writer.writeValue "0x" & Bytes(value).toHex

template readValue*(reader: var JsonReader, value: var BitList) =
  type T = type(value)
  value = T readValue(reader, BitSeq)

template writeValue*(writer: var JsonWriter, value: BitList) =
  writeValue(writer, BitSeq value)

template init*(T: type BitList, len: int): auto = T init(BitSeq, len)
template len*(x: BitList): auto = len(BitSeq(x))
template bytes*(x: BitList): auto = bytes(BitSeq(x))
template `[]`*(x: BitList, idx: auto): auto = BitSeq(x)[idx]
template `[]=`*(x: var BitList, idx: auto, val: bool) = BitSeq(x)[idx] = val
template `==`*(a, b: BitList): bool = BitSeq(a) == BitSeq(b)
template raiseBit*(x: var BitList, idx: int) = raiseBit(BitSeq(x), idx)
template lowerBit*(x: var BitList, idx: int) = lowerBit(BitSeq(x), idx)
template overlaps*(a, b: BitList): bool = overlaps(BitSeq(a), BitSeq(b))
template combine*(a: var BitList, b: BitList) = combine(BitSeq(a), BitSeq(b))
template isSubsetOf*(a, b: BitList): bool = isSubsetOf(BitSeq(a), BitSeq(b))
template `$`*(a: BitList): string = $(BitSeq(a))

when useListType:
  template len*[T; N](x: List[T, N]): auto = len(seq[T](x))
  template `[]`*[T; N](x: List[T, N], idx: auto): auto = seq[T](x)[idx]
  template `[]=`*[T; N](x: List[T, N], idx: auto, val: bool) = seq[T](x)[idx] = val
  template `==`*[T; N](a, b: List[T, N]): bool = seq[T](a) == seq[T](b)
  template asSeq*[T; N](x: List[T, N]): auto = seq[T](x)
  template `&`*[T; N](a, b: List[T, N]): List[T, N] = seq[T](a) & seq[T](b)
else:
  template asSeq*[T; N](x: List[T, N]): auto = x

func shortLog*(s: Slot): uint64 =
  s - GENESIS_SLOT

func shortLog*(e: Epoch): uint64 =
  e - GENESIS_EPOCH

func shortLog*(v: BeaconBlock): tuple[
    slot: uint64, parent_root: string, state_root: string,
    #[ eth1_data ]#
    proposer_slashings_len: int, attester_slashings_len: int,
    attestations_len: int,
    deposits_len: int,
    voluntary_exits_len: int,
    transfers_len: int,
    signature: string
  ] = (
    shortLog(v.slot), shortLog(v.parent_root),
    shortLog(v.state_root), v.body.proposer_slashings.len(),
    v.body.attester_slashings.len(), v.body.attestations.len(),
    v.body.deposits.len(), v.body.voluntary_exits.len(), v.body.transfers.len(),
    shortLog(v.signature)
  )

func shortLog*(v: AttestationData): auto =
   (
      shortLog(v.beacon_block_root),
      shortLog(v.source.epoch), shortLog(v.target.root),
      shortLog(v.source.root),
      v.crosslink
    )

chronicles.formatIt Slot: it.shortLog
chronicles.formatIt Epoch: it.shortLog
chronicles.formatIt BeaconBlock: it.shortLog
chronicles.formatIt AttestationData: it.shortLog

static:
  # Ensure that get_crosslink_committee(...) can access all committees, which
  # requires that SHARD_COUNT >= get_committee_count(...)
  doAssert SHARD_COUNT >= SLOTS_PER_EPOCH

import nimcrypto, json_serialization
export json_serialization
export writeValue, readValue, append, read
