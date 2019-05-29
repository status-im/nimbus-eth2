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
  hashes, math, json,
  chronicles, eth/[common, rlp],
  ./bitfield, ./crypto, ./digest

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
# https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/configs/constant_presets/
const const_preset*{.strdefine.} = "mainnet"

when const_preset == "mainnet":
  import ./presets/mainnet
  export mainnet
elif const_preset == "minimal":
  import ./presets/minimal
  export minimal
else:
  {.fatal: "Preset \"" & const_preset ".nim\" is not supported.".}

const
  SPEC_VERSION* = "0.6.1" ## \
  ## Spec version we're aiming to be compatible with, right now
  ## TODO: improve this scheme once we can negotiate versions in protocol

  # Misc
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#misc

  # TODO remove, not in post-0.5.1
  MAX_BALANCE_CHURN_QUOTIENT* = 2^5 ##\

  # Gwei values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#gwei-values

  # TODO remove erstwhile blob/v0.6.2
  FORK_CHOICE_BALANCE_INCREMENT* = 2'u64^0 * 10'u64^9

  # Initial values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#initial-values
  GENESIS_EPOCH* = (GENESIS_SLOT.uint64 div SLOTS_PER_EPOCH).Epoch ##\
  ## slot_to_epoch(GENESIS_SLOT)
  GENESIS_START_SHARD* = 0'u64
  ZERO_HASH* = Eth2Digest()
  EMPTY_SIGNATURE* = ValidatorSig()

type
  ValidatorIndex* = range[0'u32 .. 0xFFFFFF'u32] # TODO: wrap-around

  Shard* = uint64
  Gwei* = uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#proposerslashing
  ProposerSlashing* = object
    proposer_index*: uint64 ##\
    ## Proposer index

    header_1*: BeaconBlockHeader ##\
    # First block header

    header_2*: BeaconBlockHeader ##\
    # Second block header

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#attesterslashing
  AttesterSlashing* = object
    attestation_1*: IndexedAttestation ## \
    ## First attestation
    attestation_2*: IndexedAttestation ## \
    ## Second attestation

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#slashableattestation
  IndexedAttestation* = object
    validator_indices*: seq[uint64] ##\
    ## Validator indices

    data*: AttestationData ## \
    ## Attestation data

    custody_bitfield*: BitField ##\
    ## Custody bitfield

    aggregate_signature*: ValidatorSig ## \
    ## Aggregate signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#attestation
  Attestation* = object
    aggregation_bitfield*: BitField ##\
    ## Attester aggregation bitfield

    data*: AttestationData ##\
    ## Attestation data

    custody_bitfield*: BitField ##\
    ## Custody bitfield

    aggregate_signature*: ValidatorSig ##\
    ## BLS aggregate signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.0/specs/core/0_beacon-chain.md#attestationdata
  AttestationData* = object
    # LMD GHOST vote
    slot*: Slot
    beacon_block_root*: Eth2Digest

    # FFG vote
    source_epoch*: Epoch
    source_root*: Eth2Digest
    target_epoch*: Epoch
    target_root*: Eth2Digest

    # Crosslink vote
    shard*: uint64
    previous_crosslink*: Crosslink
    crosslink_data_root*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#attestationdataandcustodybit
  AttestationDataAndCustodyBit* = object
    data*: AttestationData
    custody_bit*: bool

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#deposit
  Deposit* = object
    proof*: array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest] ##\
    ## Branch in the deposit tree

    index*: uint64 ##\
    ## Index in the deposit tree

    data*: DepositData ##\
    ## Data

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#depositdata
  DepositData* = object
    pubkey*: ValidatorPubKey ##\
    ## BLS pubkey

    withdrawal_credentials*: Eth2Digest ##\
    ## Withdrawal credentials

    amount*: uint64 ##\
    ## Amount in Gwei

    dummy*: uint64

    signature*: ValidatorSig ##\
    ## Container self-signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#voluntaryexit
  VoluntaryExit* = object
    # Minimum epoch for processing exit
    epoch*: Epoch
    # Index of the exiting validator
    validator_index*: uint64
    # Validator signature
    signature*: ValidatorSig

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#transfer
  Transfer* = object
    sender*: uint64 ##\
    ## Sender index

    recipient*: uint64 ##\
    ## Recipient index

    amount*: uint64 ##\
    ## Amount in Gwei

    fee*: uint64 ##\
    ## Fee in Gwei for block proposer

    slot*: uint64 ##\
    ## Inclusion slot

    pubkey*: ValidatorPubKey ##\
    ## Sender withdrawal pubkey

    signature*: ValidatorSig ##\
    ## Sender signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#beaconblock
  BeaconBlock* = object
    ## For each slot, a proposer is chosen from the validator pool to propose
    ## a new block. Once the block as been proposed, it is transmitted to
    ## validators that will have a chance to vote on it through attestations.
    ## Each block collects attestations, or votes, on past blocks, thus a chain
    ## is formed.

    slot*: Slot

    previous_block_root*: Eth2Digest ##\
    ##\ Root hash of the previous block

    state_root*: Eth2Digest ##\
    ## The state root, _after_ this block has been processed

    body*: BeaconBlockBody

    signature*: ValidatorSig ##\
    ## Proposer signature

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#beaconblockheader
  BeaconBlockHeader* = object
    slot*: Slot
    previous_block_root*: Eth2Digest
    state_root*: Eth2Digest
    block_body_root*: Eth2Digest
    signature*: ValidatorSig

  BeaconBlockHeaderRLP* = object
    ## Same as BeaconBlock, except `body` is the `hash_tree_root` of the
    ## associated BeaconBlockBody.
    # TODO: Dry it up with BeaconBlock
    # TODO: As a first step, don't change RLP output; only previous user,
    # but as with others, randao_reveal and eth1_data move to body.
    # This is from before spec had a version.
    slot*: uint64
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data
    signature*: ValidatorSig
    body*: Eth2Digest

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#beaconblockbody
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

  # https://github.com/ethereum/eth2.0-specs/blob/v0.5.1/specs/core/0_beacon-chain.md#beaconstate
  BeaconState* = object
    slot*: Slot
    genesis_time*: uint64
    fork*: Fork ##\
    ## For versioning hard forks

    # Validator registry
    validator_registry*: seq[Validator]
    balances*: seq[uint64] ##\
    ## Validator balances in Gwei!

    validator_registry_update_epoch*: Epoch

    # Randomness and committees
    latest_randao_mixes*: array[LATEST_RANDAO_MIXES_LENGTH, Eth2Digest]
    latest_start_shard*: Shard
    previous_shuffling_start_shard*: uint64
    current_shuffling_start_shard*: uint64
    previous_shuffling_epoch*: Epoch
    current_shuffling_epoch*: Epoch
    previous_shuffling_seed*: Eth2Digest
    current_shuffling_seed*: Eth2Digest

    # Finality
    previous_epoch_attestations*: seq[PendingAttestation]
    current_epoch_attestations*: seq[PendingAttestation]
    previous_justified_epoch*: Epoch
    current_justified_epoch*: Epoch
    previous_justified_root*: Eth2Digest
    current_justified_root*: Eth2Digest
    justification_bitfield*: uint64
    finalized_epoch*: Epoch
    finalized_root*: Eth2Digest

    # Recent state
    latest_crosslinks*: array[SHARD_COUNT, Crosslink]
    latest_block_roots*: array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## Needed to process attestations, older to newer
    latest_state_roots*: array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest]
    latest_active_index_roots*: array[LATEST_ACTIVE_INDEX_ROOTS_LENGTH, Eth2Digest]

    latest_slashed_balances*: array[LATEST_SLASHED_EXIT_LENGTH, uint64] ##\
    ## Balances penalized in the current withdrawal period

    latest_block_header*: BeaconBlockHeader ##\
    ## `latest_block_header.state_root == ZERO_HASH` temporarily
    historical_roots*: seq[Eth2Digest]

    # Ethereum 1.0 chain data
    latest_eth1_data*: Eth1Data
    eth1_data_votes*: seq[Eth1Data]
    deposit_index*: uint64

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.1/specs/core/0_beacon-chain.md#validator
  Validator* = object
    pubkey*: ValidatorPubKey ##\
    ## BLS public key

    withdrawal_credentials*: Eth2Digest ##\
    ## Withdrawal credentials

    activation_eligibility_epoch*: Epoch ##\
    ## Epoch when validator activated

    activation_epoch*: Epoch ##\
    ## Epoch when validator activated

    exit_epoch*: Epoch ##\
    ## Epoch when validator exited

    withdrawable_epoch*: Epoch ##\
    ## Epoch when validator is eligible to withdraw

    slashed*: bool ##\
    ## Was the validator slashed

    effective_balance*: uint64 ##\
    ## Effective balance

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#crosslink
  Crosslink* = object
    epoch*: Epoch ##\
    ## Epoch number

    previous_crosslink_root*: Eth2Digest ##\
    ## Root of the previous crosslink

    crosslink_data_root*: Eth2Digest ##\
    ## Shard data since the previous crosslink

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#pendingattestation
  PendingAttestation* = object
    aggregation_bitfield*: BitField           ## Attester participation bitfield
    data*: AttestationData                    ## Attestation data

    # TODO remove
    inclusion_slot*: Slot                     ## Inclusion slot

    inclusion_delay*: uint64                  ## Inclusion delay
    proposer_index*: ValidatorIndex           ## Proposer index

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#historicalbatch
  HistoricalBatch* = object
    block_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## Block roots

    state_roots* : array[SLOTS_PER_HISTORICAL_ROOT, Eth2Digest] ##\
    ## State roots

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#fork
  Fork* = object
    previous_version*: array[4, byte] ##\
    ## Previous fork version

    current_version*: array[4, byte] ##\
    ## Current fork version

    epoch*: Epoch ##\
    ## Fork epoch number

  # https://github.com/ethereum/eth2.0-specs/blob/v0.6.0/specs/core/0_beacon-chain.md#eth1data
  Eth1Data* = object
    deposit_root*: Eth2Digest ##\
    ## Data being voted for

    deposit_count*: uint64 ##\
    ## Total number of deposits

    block_hash*: Eth2Digest ##\
    ## Block hash

  ## TODO remove or otherwise conditional-compile this, since it's for light
  ## client but not in spec
  ValidatorSetDeltaFlags* {.pure.} = enum
    Activation = 0
    Exit = 1

  # TODO: not in spec
  CrosslinkCommittee* = tuple[committee: seq[ValidatorIndex], shard: uint64]

  # TODO to be replaced with some magic hash caching
  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root (not signing_root!)

func shortValidatorKey*(state: BeaconState, validatorIdx: int): string =
    ($state.validator_registry[validatorIdx].pubkey)[0..7]

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

  proc `+=`*(x: var typ, y: uint64) {.borrow.}
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

func humaneSlotNum*(s: Slot): uint64 =
  s - GENESIS_SLOT

func humaneEpochNum*(e: Epoch): uint64 =
  e - GENESIS_EPOCH

func shortLog*(v: BeaconBlock): tuple[
    slot: uint64, previous_block_root: string, state_root: string,
    #[ eth1_data ]#
    proposer_slashings_len: int, attester_slashings_len: int,
    attestations_len: int,
    deposits_len: int,
    voluntary_exits_len: int,
    transfers_len: int,
    signature: string
  ] = (
    humaneSlotNum(v.slot), shortLog(v.previous_block_root),
    shortLog(v.state_root), v.body.proposer_slashings.len(),
    v.body.attester_slashings.len(), v.body.attestations.len(),
    v.body.deposits.len(), v.body.voluntary_exits.len(), v.body.transfers.len(),
    shortLog(v.signature)
  )

func shortLog*(v: AttestationData): tuple[
      slot: uint64, beacon_block_root: string, source_epoch: uint64,
      target_root: string, source_root: string, shard: uint64,
      previous_crosslink_epoch: uint64, previous_crosslink_data_root: string,
      crosslink_data_root: string
    ] = (
      humaneSlotNum(v.slot), shortLog(v.beacon_block_root),
      humaneEpochNum(v.source_epoch), shortLog(v.target_root),
      shortLog(v.source_root),
      v.shard, humaneEpochNum(v.previous_crosslink.epoch),
      shortLog(v.previous_crosslink.crosslink_data_root),
      shortLog(v.crosslink_data_root)
    )

chronicles.formatIt Slot: it.humaneSlotNum
chronicles.formatIt Epoch: it.humaneEpochNum
chronicles.formatIt BeaconBlock: it.shortLog
chronicles.formatIt AttestationData: it.shortLog

import nimcrypto, json_serialization
export json_serialization
export writeValue, readValue, append, read
