# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
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
  std/macros,
  stew/assign2,
  json_serialization,
  json_serialization/types as jsonTypes,
  ../../ssz/types as sszTypes, ../digest,
  ./phase0, ./altair,
  #web3/ethtypes,
  nimcrypto/utils

const
  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#execution
  MAX_BYTES_PER_OPAQUE_TRANSACTION* = 1048576
  MAX_TRANSACTIONS_PER_PAYLOAD* = 16384
  BYTES_PER_LOGS_BLOOM = 256
  GAS_LIMIT_DENOMINATOR* = 1024
  MIN_GAS_LIMIT* = 5000
  MAX_EXTRA_DATA_BYTES = 32

type
  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#custom-types
  OpaqueTransaction* = List[byte, Limit MAX_BYTES_PER_OPAQUE_TRANSACTION]
  Transaction* = SingleMemberUnion[OpaqueTransaction]

  # TODO rename ExecutionAddress
  EthAddress* = object
    data*: array[20, byte]  # TODO there's a network_metadata type, but the import hierarchy's inconvenient

  BloomLogs* = object
    data*: array[BYTES_PER_LOGS_BLOOM, byte]

  # https://github.com/ethereum/execution-apis/blob/v1.0.0-alpha.2/src/engine/interop/specification.md#returns
  PayloadId* = uint64

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#executionpayload
  ExecutionPayload* = object
    parent_hash*: Eth2Digest
    coinbase*: EthAddress  # 'beneficiary' in the yellow paper
    state_root*: Eth2Digest
    receipt_root*: Eth2Digest # 'receipts root' in the yellow paper
    logs_bloom*: BloomLogs
    random*: Eth2Digest  # 'difficulty' in the yellow paper
    block_number*: uint64  # 'number' in the yellow paper
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: Eth2Digest  # base fee introduced in EIP-1559, little-endian serialized

    # Extra payload fields
    block_hash*: Eth2Digest # Hash of execution block
    transactions*: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#executionpayloadheader
  ExecutionPayloadHeader* = object
    parent_hash*: Eth2Digest
    coinbase*: EthAddress
    state_root*: Eth2Digest
    receipt_root*: Eth2Digest
    logs_bloom*: BloomLogs
    random*: Eth2Digest
    block_number*: uint64
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: Eth2Digest  # base fee introduced in EIP-1559, little-endian serialized

    # Extra payload fields
    block_hash*: Eth2Digest  # Hash of execution block
    transactions_root*: Eth2Digest

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#execution-engine
  ExecutePayload* = proc(
    execution_payload: ExecutionPayload): bool {.gcsafe, raises: [Defect].}

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0/specs/merge/fork-choice.md#powblock
  PowBlock* = object
    block_hash*: Eth2Digest
    parent_hash*: Eth2Digest
    total_difficulty*: Eth2Digest   # uint256
    difficulty*: Eth2Digest         # uint256

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#beaconstate
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
    previous_epoch_participation*:
      HashList[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT]
    current_epoch_participation*:
      HashList[ParticipationFlags, Limit VALIDATOR_REGISTRY_LIMIT]

    # Finality
    justification_bits*: uint8 ##\
    ## Bit set for every recent justified epoch
    ## Model a Bitvector[4] as a one-byte uint, which should remain consistent
    ## with ssz/hashing.

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
    latest_execution_payload_header*: ExecutionPayloadHeader  # [New in Merge]

  # TODO Careful, not nil analysis is broken / incomplete and the semantics will
  #      likely change in future versions of the language:
  #      https://github.com/nim-lang/RFCs/issues/250
  BeaconStateRef* = ref BeaconState not nil
  NilableBeaconStateRef* = ref BeaconState

  HashedBeaconState* = object
    data*: BeaconState
    root*: Eth2Digest # hash_tree_root(data)

  SomeBeaconState* = BeaconState | altair.BeaconState | phase0.BeaconState
  SomeHashedBeaconState* = HashedBeaconState | altair.HashedBeaconState | phase0.HashedBeaconState

  # https://github.com/ethereum/consensus-specs/blob/v1.0.1/specs/phase0/beacon-chain.md#beaconblock
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

  # https://github.com/ethereum/consensus-specs/blob/v1.1.0-beta.4/specs/merge/beacon-chain.md#beaconblockbody
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
    sync_aggregate*: SyncAggregate

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
    sync_aggregate*: SyncAggregate

    # Execution
    execution_payload*: ExecutionPayload  # [New in Merge]

  # https://github.com/ethereum/consensus-specs/blob/v1.1.2/specs/phase0/beacon-chain.md#signedbeaconblock
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

  # TODO why does this fail?
  #SomeSomeBeaconBlock* = SomeBeaconBlock | phase0.SomeBeaconBlock
  SomeSomeBeaconBlock* =
    BeaconBlock | SigVerifiedBeaconBlock | TrustedBeaconBlock |
    altair.BeaconBlock | altair.SigVerifiedBeaconBlock | altair.TrustedBeaconBlock |
    phase0.BeaconBlock | phase0.SigVerifiedBeaconBlock | phase0.TrustedBeaconBlock

  # TODO see above, re why does it fail
  SomeSomeBeaconBlockBody* =
    BeaconBlockBody | SigVerifiedBeaconBlockBody | TrustedBeaconBlockBody |
    altair.BeaconBlockBody | altair.SigVerifiedBeaconBlockBody | altair.TrustedBeaconBlockBody |
    phase0.BeaconBlockBody | phase0.SigVerifiedBeaconBlockBody | phase0.TrustedBeaconBlockBody
  #SomeSomeBeaconBlockBody* = SomeBeaconBlockBody | phase0.SomeBeaconBlockBody

  SomeSomeSignedBeaconBlock* = SomeSignedBeaconBlock | altair.SomeSignedBeaconBlock | phase0.SomeSignedBeaconBlock

  BlockParams* = object
    parentHash*: string
    timestamp*: string

  BoolReturnValidRPC* = object
    valid*: bool

  BoolReturnSuccessRPC* = object
    success*: bool

func encodeQuantityHex*(x: auto): string =
  "0x" & x.toHex

proc fromHex*(T: typedesc[BloomLogs], s: string): T =
  hexToBytes(s, result.data)

proc fromHex*(T: typedesc[EthAddress], s: string): T =
  hexToBytes(s, result.data)

proc writeValue*(w: var JsonWriter, a: EthAddress) {.raises: [Defect, IOError, SerializationError].} =
  w.writeValue $a

proc readValue*(r: var JsonReader, a: var EthAddress) {.raises: [Defect, IOError, SerializationError].} =
  try:
    a = fromHex(type(a), r.readValue(string))
  except ValueError:
    raiseUnexpectedValue(r, "Hex string expected")

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
