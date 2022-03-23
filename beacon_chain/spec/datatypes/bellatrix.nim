# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# TODO Careful, not nil analysis is broken / incomplete and the semantics will
#      likely change in future versions of the language:
#      https://github.com/nim-lang/RFCs/issues/250
{.experimental: "notnil".}

{.push raises: [Defect].}

import
  stew/byteutils,
  json_serialization,
  ssz_serialization/types as sszTypes,
  ../digest,
  "."/[base, phase0, altair]

export json_serialization, base

const
  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/bellatrix/beacon-chain.md#transition-settings
  TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH* = FAR_FUTURE_EPOCH

type
  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/bellatrix/beacon-chain.md#custom-types
  Transaction* = List[byte, Limit MAX_BYTES_PER_TRANSACTION]

  ExecutionAddress* = object
    data*: array[20, byte]  # TODO there's a network_metadata type, but the import hierarchy's inconvenient

  BloomLogs* = object
    data*: array[BYTES_PER_LOGS_BLOOM, byte]

  PayloadID* = array[8, byte]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.7/specs/merge/beacon-chain.md#executionpayload
  ExecutionPayload* = object
    parent_hash*: Eth2Digest
    fee_recipient*: ExecutionAddress  # 'beneficiary' in the yellow paper
    state_root*: Eth2Digest
    receipts_root*: Eth2Digest # 'receipts root' in the yellow paper
    logs_bloom*: BloomLogs
    prev_randao*: Eth2Digest  # 'difficulty' in the yellow paper
    block_number*: uint64  # 'number' in the yellow paper
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: Eth2Digest  # base fee introduced in EIP-1559, little-endian serialized

    # Extra payload fields
    block_hash*: Eth2Digest # Hash of execution block
    transactions*: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.7/specs/merge/beacon-chain.md#executionpayloadheader
  ExecutionPayloadHeader* = object
    parent_hash*: Eth2Digest
    fee_recipient*: ExecutionAddress
    state_root*: Eth2Digest
    receipts_root*: Eth2Digest
    logs_bloom*: BloomLogs
    prev_randao*: Eth2Digest
    block_number*: uint64
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: Eth2Digest  # base fee introduced in EIP-1559, little-endian serialized

    # Extra payload fields
    block_hash*: Eth2Digest  # Hash of execution block
    transactions_root*: Eth2Digest

  ExecutePayload* = proc(
    execution_payload: ExecutionPayload): bool {.gcsafe, raises: [Defect].}

  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/bellatrix/fork-choice.md#powblock
  PowBlock* = object
    block_hash*: Eth2Digest
    parent_hash*: Eth2Digest
    total_difficulty*: Eth2Digest   # uint256

  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/bellatrix/beacon-chain.md#beaconstate
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

    # Participation
    previous_epoch_participation*: EpochParticipationFlags
    current_epoch_participation*: EpochParticipationFlags

    # Finality
    justification_bits*: JustificationBits

    previous_justified_checkpoint*: Checkpoint ##\
    ## Previous epoch snapshot

    current_justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint

    # Inactivity
    inactivity_scores*: HashList[uint64, Limit VALIDATOR_REGISTRY_LIMIT]

    # Sync
    current_sync_committee*: SyncCommittee
    next_sync_committee*: SyncCommittee

    # Execution
    latest_execution_payload_header*: ExecutionPayloadHeader  # [New in Bellatrix]

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/phase0/beacon-chain.md#beaconblock
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

  SigVerifiedBeaconBlock* = object
    ## A BeaconBlock that contains verified signatures
    ## but that has not been verified for state transition
    slot*: Slot
    proposer_index*: uint64

    parent_root*: Eth2Digest ##\
    ## Root hash of the previous block

    state_root*: Eth2Digest ##\
    ## The state root, _after_ this block has been processed

    body*: SigVerifiedBeaconBlockBody

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

  # https://github.com/ethereum/consensus-specs/blob/v1.1.7/specs/merge/beacon-chain.md#beaconblockbody
  BeaconBlockBody* = object
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data ##\
    ## Eth1 data vote

    graffiti*: GraffitiBytes ##\
    ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: SyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [New in Merge]

  SigVerifiedBeaconBlockBody* = object
    ## A BeaconBlock body with signatures verified
    ## including:
    ## - Randao reveal
    ## - Attestations
    ## - ProposerSlashing (SignedBeaconBlockHeader)
    ## - AttesterSlashing (IndexedAttestation)
    ## - SignedVoluntaryExits
    ##
    ## - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    randao_reveal*: ValidatorSig
    eth1_data*: Eth1Data ##\
    ## Eth1 data vote

    graffiti*: GraffitiBytes ##\
    ## Arbitrary data

    # Operations
    proposer_slashings*: List[ProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[AttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[Attestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[SignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: SyncAggregate # TODO TrustedSyncAggregate after batching

    # Execution
    execution_payload*: ExecutionPayload  # [New in Merge]

  TrustedBeaconBlockBody* = object
    ## A full verified block
    randao_reveal*: TrustedSig
    eth1_data*: Eth1Data ##\
    ## Eth1 data vote

    graffiti*: GraffitiBytes ##\
    ## Arbitrary data

    # Operations
    proposer_slashings*: List[TrustedProposerSlashing, Limit MAX_PROPOSER_SLASHINGS]
    attester_slashings*: List[TrustedAttesterSlashing, Limit MAX_ATTESTER_SLASHINGS]
    attestations*: List[TrustedAttestation, Limit MAX_ATTESTATIONS]
    deposits*: List[Deposit, Limit MAX_DEPOSITS]
    voluntary_exits*: List[TrustedSignedVoluntaryExit, Limit MAX_VOLUNTARY_EXITS]
    sync_aggregate*: TrustedSyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [New in Merge]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.10/specs/phase0/beacon-chain.md#signedbeaconblock
  SignedBeaconBlock* = object
    message*: BeaconBlock
    signature*: ValidatorSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SigVerifiedSignedBeaconBlock* = object
    ## A SignedBeaconBlock with signatures verified
    ## including:
    ## - Block signature
    ## - BeaconBlockBody
    ##   - Randao reveal
    ##   - Attestations
    ##   - ProposerSlashing (SignedBeaconBlockHeader)
    ##   - AttesterSlashing (IndexedAttestation)
    ##   - SignedVoluntaryExits
    ##
    ##   - ETH1Data (Deposits) can contain invalid BLS signatures
    ##
    ## The block state transition has NOT been verified
    message*: SigVerifiedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  TrustedSignedBeaconBlock* = object
    message*: TrustedBeaconBlock
    signature*: TrustedSig

    root* {.dontSerialize.}: Eth2Digest # cached root of signed beacon block

  SomeSignedBeaconBlock* = SignedBeaconBlock | SigVerifiedSignedBeaconBlock | TrustedSignedBeaconBlock
  SomeBeaconBlock* = BeaconBlock | SigVerifiedBeaconBlock | TrustedBeaconBlock
  SomeBeaconBlockBody* = BeaconBlockBody | SigVerifiedBeaconBlockBody | TrustedBeaconBlockBody

  BlockParams = object
    parentHash*: string
    timestamp*: string

  BoolReturnValidRPC = object
    valid*: bool

  BoolReturnSuccessRPC = object
    success*: bool

func encodeQuantityHex*(x: auto): string =
  "0x" & x.toHex

func fromHex*(T: typedesc[BloomLogs], s: string): T {.
     raises: [Defect, ValueError].} =
  hexToByteArray(s, result.data)

func fromHex*(T: typedesc[ExecutionAddress], s: string): T {.
     raises: [Defect, ValueError].} =
  hexToByteArray(s, result.data)

proc writeValue*(writer: var JsonWriter, value: ExecutionAddress) {.
     raises: [Defect, IOError].} =
  writer.writeValue to0xHex(value.data)

proc readValue*(reader: var JsonReader, value: var ExecutionAddress) {.
     raises: [Defect, IOError, SerializationError].} =
  try:
    hexToByteArray(reader.readValue(string), value.data)
  except ValueError:
    raiseUnexpectedValue(reader,
                         "ExecutionAddress value should be a valid hex string")

func shortLog*(v: SomeBeaconBlock): auto =
  (
    slot: shortLog(v.slot),
    proposer_index: v.proposer_index,
    parent_root: shortLog(v.parent_root),
    state_root: shortLog(v.state_root),
    eth1data: v.body.eth1_data,
    graffiti: $v.body.graffiti,
    proposer_slashings_len: v.body.proposer_slashings.len(),
    attester_slashings_len: v.body.attester_slashings.len(),
    attestations_len: v.body.attestations.len(),
    deposits_len: v.body.deposits.len(),
    voluntary_exits_len: v.body.voluntary_exits.len(),
    sync_committee_participants: countOnes(v.body.sync_aggregate.sync_committee_bits)
  )

func shortLog*(v: SomeSignedBeaconBlock): auto =
  (
    blck: shortLog(v.message),
    signature: shortLog(v.signature)
  )

template asSigned*(x: SigVerifiedSignedBeaconBlock | TrustedSignedBeaconBlock):
    SignedBeaconBlock =
  isomorphicCast[SignedBeaconBlock](x)

template asSigVerified*(x: SignedBeaconBlock | TrustedSignedBeaconBlock): SigVerifiedSignedBeaconBlock =
  isomorphicCast[SigVerifiedSignedBeaconBlock](x)

template asTrusted*(
    x: SignedBeaconBlock | SigVerifiedSignedBeaconBlock): TrustedSignedBeaconBlock =
  isomorphicCast[TrustedSignedBeaconBlock](x)
