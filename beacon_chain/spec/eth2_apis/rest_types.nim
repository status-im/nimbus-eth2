# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Types used by both client and server in the common REST API:
# https://ethereum.github.io/beacon-APIs/
# Be mindful that changing these changes the serialization and deserialization
# in the API which may lead to incompatibilities between clients - tread
# carefully!

{.push raises: [].}

import
  std/[json, tables],
  stew/base10, web3/primitives, httputils,
  ".."/forks,
  ".."/datatypes/[phase0, altair, bellatrix, deneb],
  ".."/mev/[capella_mev, deneb_mev]

from ".."/datatypes/capella import BeaconBlockBody

export forks, phase0, altair, bellatrix, capella, capella_mev, deneb_mev,
       tables, httputils

const
  # https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/states/validator_balances.yaml#L17
  # https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/states/validators.yaml#L17
  # Maximum number of validators that can be served by the REST server in one
  # request, if the number of validator exceeds this value REST server
  # will return HTTP error 400.
  ServerMaximumValidatorIds* = 16384

  # https://github.com/ethereum/beacon-APIs/blob/2.3.x/apis/beacon/states/validators.yaml#L23
  # Maximum number of validators that can be sent in single request by
  # validator client (VC).
  ClientMaximumValidatorIds* = 30

  # https://github.com/ethereum/beacon-APIs/blob/master/apis/validator/duties/attester.yaml#L32
  # https://github.com/ethereum/beacon-APIs/blob/master/apis/validator/duties/sync.yaml#L16
  # Maximum number of validator ids sent with validator client's duties
  # requests. Validator ids are sent in decimal encoding with comma, so
  # number of ids should not exceed beacon node's `rest-max-body-size`.
  DutiesMaximumValidatorIds* = 16384

const
  preferSSZ* = "application/octet-stream,application/json;q=0.9"

static:
  doAssert(ClientMaximumValidatorIds <= ServerMaximumValidatorIds)

type
  EventTopic* {.pure.} = enum
    Head, Block, Attestation, VoluntaryExit, FinalizedCheckpoint, ChainReorg,
    ContributionAndProof, LightClientFinalityUpdate, LightClientOptimisticUpdate

  EventTopics* = set[EventTopic]

  RestValidatorIndex* = distinct uint64

  ValidatorQueryKind* {.pure.} = enum
    Index, Key

  ValidatorIndexError* {.pure.} = enum
    UnsupportedValue, TooHighValue

  ValidatorIdent* = object
    case kind*: ValidatorQueryKind
    of ValidatorQueryKind.Index:
      index*: RestValidatorIndex
    of ValidatorQueryKind.Key:
      key*: ValidatorPubKey

  ValidatorFilterKind* {.pure.} = enum
    PendingInitialized, PendingQueued,
    ActiveOngoing, ActiveExiting, ActiveSlashed,
    ExitedUnslashed, ExitedSlashed,
    WithdrawalPossible, WithdrawalDone

  ValidatorFilter* = set[ValidatorFilterKind]

  StateQueryKind* {.pure.} = enum
    Slot, Root, Named

  StateIdentType* {.pure.} = enum
    Head, Genesis, Finalized, Justified

  BroadcastValidationType* {.pure.} = enum
    Gossip, Consensus, ConsensusAndEquivocation

  StateIdent* = object
    case kind*: StateQueryKind
    of StateQueryKind.Slot:
      slot*: Slot
    of StateQueryKind.Root:
      root*: Eth2Digest
    of StateQueryKind.Named:
      value*: StateIdentType

  BlockQueryKind* {.pure.} = enum
    Slot, Root, Named
  BlockIdentType* {.pure.} = enum
    Head, Genesis, Finalized

  BlockIdent* = object
    case kind*: BlockQueryKind
    of BlockQueryKind.Slot:
      slot*: Slot
    of BlockQueryKind.Root:
      root*: Eth2Digest
    of BlockQueryKind.Named:
      value*: BlockIdentType

  PeerStateKind* {.pure.} = enum
    Disconnected, Connecting, Connected, Disconnecting

  PeerDirectKind* {.pure.} = enum
    Inbound, Outbound

  RestNumeric* = distinct int

  RestValidatorRequest* = object
    ids*: Opt[seq[ValidatorIdent]]
    status*: Opt[ValidatorFilter]

  RestAttesterDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    committee_index*: CommitteeIndex
    committee_length*: uint64
    committees_at_slot*: uint64
    validator_committee_index*: uint64
    slot*: Slot

  RestProposerDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    slot*: Slot

  RestSyncCommitteeDuty* = object
    pubkey*: ValidatorPubKey
    validator_index*: ValidatorIndex
    validator_sync_committee_indices*: seq[IndexInSyncCommittee]

  RestSyncCommitteeMessage* = object
    slot*: Slot
    beacon_block_root*: Eth2Digest
    validator_index*: uint64
    signature*: ValidatorSig

  RestSyncCommitteeContribution* = object
    slot*: Slot
    beacon_block_root*: Eth2Digest
    subcommittee_index*: uint64
    aggregation_bits*: SyncCommitteeAggregationBits
    signature*: ValidatorSig

  RestContributionAndProof* = object
    aggregator_index*: uint64
    selection_proof*: ValidatorSig
    contribution*: RestSyncCommitteeContribution

  RestSignedContributionAndProof* = object
    message*: RestContributionAndProof
    signature*: ValidatorSig

  RestCommitteeSubscription* = object
    validator_index*: ValidatorIndex
    committee_index*: CommitteeIndex
    committees_at_slot*: uint64
    slot*: Slot
    is_aggregator*: bool

  RestSyncCommitteeSubscription* = object
    validator_index*: ValidatorIndex
    sync_committee_indices*: seq[IndexInSyncCommittee]
    until_epoch*: Epoch

  RestBeaconStatesFinalityCheckpoints* = object
    previous_justified*: Checkpoint
    current_justified*: Checkpoint
    finalized*: Checkpoint

  RestGenesis* = object
    genesis_time*: uint64
    genesis_validators_root*: Eth2Digest
    genesis_fork_version*: Version

  RestValidatorBalance* = object
    index*: ValidatorIndex
    balance*: string

  RestBeaconStatesCommittees* = object
    index*: CommitteeIndex
    slot*: Slot
    validators*: seq[ValidatorIndex]

  RestErrorMessage* = object
    ## https://github.com/ethereum/beacon-APIs/blob/v2.4.0/types/http.yaml#L130
    code*: int
    message*: string
    stacktraces*: Opt[seq[string]]

  RestIndexedErrorMessage* = object
    ## https://github.com/ethereum/beacon-APIs/blob/v2.4.0/types/http.yaml#L145
    code*: int
    message*: string
    failures*: seq[RestIndexedErrorMessageItem]

  RestIndexedErrorMessageItem* = object
    index*: int
    message*: string

  RestValidator* = object
    index*: ValidatorIndex
    balance*: string
    status*: string
    validator*: Validator

  RestBlockHeader* = object
    slot*: Slot
    proposer_index*: ValidatorIndex
    parent_root*: Eth2Digest
    state_root*: Eth2Digest
    body_root*: Eth2Digest

  RestSignedBlockHeader* = object
    message*: RestBlockHeader
    signature*: ValidatorSig

  RestBlockHeaderInfo* = object
    root*: Eth2Digest
    canonical*: bool
    header*: RestSignedBlockHeader

  RestNodePeer* = object
    peer_id*: string
    enr*: string
    last_seen_p2p_address*: string
    state*: string
    direction*: string
    agent*: string # This is not part of specification
    proto*: string # This is not part of specification

  RestNodeVersion* = object
    version*: string

  RestSyncInfo* = object
    head_slot*: Slot
    sync_distance*: uint64
    is_syncing*: bool
    is_optimistic*: Option[bool]
    el_offline*: Option[bool]

  RestPeerCount* = object
    disconnected*: uint64
    connecting*: uint64
    connected*: uint64
    disconnecting*: uint64

  RestChainHead* = object
    root*: Eth2Digest
    slot*: Slot

  RestMetadata* = object
    seq_number*: string
    syncnets*: string
    attnets*: string

  RestNetworkIdentity* = object
    peer_id*: string
    enr*: string
    p2p_addresses*: seq[string]
    discovery_addresses*: seq[string]
    metadata*: RestMetadata

  RestActivityItem* = object
    index*: ValidatorIndex
    epoch*: Epoch
    active*: bool

  RestLivenessItem* = object
    index*: ValidatorIndex
    is_live*: bool

  RestWithdrawalPrefix* = distinct array[1, byte]

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/capella/beacon-chain.md#executionpayload
  RestExecutionPayload* = object
    # Execution block header fields
    parent_hash*: Eth2Digest
    fee_recipient*: ExecutionAddress
      ## 'beneficiary' in the yellow paper
    state_root*: Eth2Digest
    receipts_root*: Eth2Digest
    logs_bloom*: BloomLogs
    prev_randao*: Eth2Digest
      ## 'difficulty' in the yellow paper
    block_number*: uint64
      ## 'number' in the yellow paper
    gas_limit*: uint64
    gas_used*: uint64
    timestamp*: uint64
    extra_data*: List[byte, MAX_EXTRA_DATA_BYTES]
    base_fee_per_gas*: UInt256

    # Extra payload fields
    block_hash*: Eth2Digest
      ## Hash of execution block
    transactions*: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]
    withdrawals*: Option[List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]]
      ## [New in Capella]
    blob_gas_used*: Option[uint64]   ## [New in Deneb]
    excess_blob_gas*: Option[uint64] ## [New in Deneb]


  PrepareBeaconProposer* = object
    validator_index*: ValidatorIndex
    fee_recipient*: Eth1Address

  RestPublishedSignedBeaconBlock* = distinct ForkedSignedBeaconBlock

  DenebSignedBlockContents* = object
    signed_block*: deneb.SignedBeaconBlock
    kzg_proofs*: deneb.KzgProofs
    blobs*: deneb.Blobs

  RestPublishedSignedBlockContents* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.SignedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.SignedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     DenebSignedBlockContents

  RestPublishedBeaconBlock* = distinct ForkedBeaconBlock

  RestPublishedBeaconBlockBody* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Body*:    phase0.BeaconBlockBody
    of ConsensusFork.Altair:    altairBody*:    altair.BeaconBlockBody
    of ConsensusFork.Bellatrix: bellatrixBody*: bellatrix.BeaconBlockBody
    of ConsensusFork.Capella:   capellaBody*:   capella.BeaconBlockBody
    of ConsensusFork.Deneb:     denebBody*:     deneb.BeaconBlockBody

  ProduceBlockResponseV2* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.BeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.BeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.BeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.BeaconBlock
    of ConsensusFork.Deneb:     denebData*:     deneb.BlockContents

  VCRuntimeConfig* = Table[string, string]

  RestDepositContract* = object
    chain_id*: string
    address*: string

  RestDepositSnapshot* = object
    finalized*: array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]
    deposit_root*: Eth2Digest
    deposit_count*: uint64
    execution_block_hash*: Eth2Digest
    execution_block_height*: uint64

  RestBlockInfo* = object
    slot*: Slot
    blck* {.serializedFieldName: "block".}: Eth2Digest

  RestEpochSyncCommittee* = object
    validators*: seq[ValidatorIndex]
    validator_aggregates*: seq[seq[ValidatorIndex]]

  RestEpochRandao* = object
    randao*: Eth2Digest

  DataEnclosedObject*[T] = object
    data*: T

  DataMetaEnclosedObject*[T] = object
    data*: T
    meta*: JsonNode

  DataVersionEnclosedObject*[T] = object
    data*: T
    version*: JsonNode

  DataRootEnclosedObject*[T] = object
    dependent_root*: Eth2Digest
    data*: T
    execution_optimistic*: Option[bool]

  DataOptimisticObject*[T] = object
    data*: T
    execution_optimistic*: Option[bool]

  DataOptimisticAndFinalizedObject*[T] = object
    data*: T
    execution_optimistic*: Option[bool]
    finalized*: Option[bool]

  ForkedSignedBlockHeader* = object
    message*: uint32 # message offset
    signature*: ValidatorSig
    slot*: Slot

  Web3SignerKeysResponse* = seq[ValidatorPubKey]

  Web3SignerStatusResponse* = object
    status*: string

  Web3SignerSignatureResponse* = object
    signature*: ValidatorSig

  Web3SignerErrorResponse* = object
    error*: string

  Web3SignerForkInfo* = object
    fork*: Fork
    genesis_validators_root*: Eth2Digest

  Web3SignerAggregationSlotData* = object
    slot*: Slot

  Web3SignerRandaoRevealData* = object
    epoch*: Epoch

  Web3SignerDepositData* = object
    pubkey*: ValidatorPubKey
    withdrawalCredentials* {.
      serializedFieldName: "withdrawal_credentials".}: Eth2Digest
    genesisForkVersion* {.
      serializedFieldName: "genesis_fork_version".}: Version
    amount*: Gwei

  Web3SignerSyncCommitteeMessageData* = object
    beaconBlockRoot* {.
      serializedFieldName: "beacon_block_root".}: Eth2Digest
    slot*: Slot

  # https://consensys.github.io/web3signer/web3signer-eth2.html#operation/ETH2_SIGN
  Web3SignerValidatorRegistration* = object
    feeRecipient* {.
      serializedFieldName: "fee_recipient".}: string
    gasLimit* {.
      serializedFieldName: "gas_limit".}: uint64
    timestamp*: uint64
    pubkey*: ValidatorPubKey

  Web3SignerMerkleProof* = object
    index*: GeneralizedIndex
    proof*: seq[Eth2Digest]

  Web3SignerRequestKind* {.pure.} = enum
    AggregationSlot, AggregateAndProof, Attestation, BlockV2,
    Deposit, RandaoReveal, VoluntaryExit, SyncCommitteeMessage,
    SyncCommitteeSelectionProof, SyncCommitteeContributionAndProof,
    ValidatorRegistration

  Web3SignerRequest* = object
    signingRoot*: Opt[Eth2Digest]
    forkInfo* {.serializedFieldName: "fork_info".}: Opt[Web3SignerForkInfo]
    case kind* {.dontSerialize.}: Web3SignerRequestKind
    of Web3SignerRequestKind.AggregationSlot:
      aggregationSlot* {.
        serializedFieldName: "aggregation_slot".}: Web3SignerAggregationSlotData
    of Web3SignerRequestKind.AggregateAndProof:
      aggregateAndProof* {.
        serializedFieldName: "aggregate_and_proof".}: AggregateAndProof
    of Web3SignerRequestKind.Attestation:
      attestation*: AttestationData
    of Web3SignerRequestKind.BlockV2:
      # https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing/operation/ETH2_SIGN
      # https://github.com/Consensys/web3signer/blob/2d956c019663ac70f60640d23196d1d321c1b1fa/core/src/main/resources/openapi-specs/eth2/signing/schemas.yaml#L483-L500
      beaconBlockHeader* {.
        serializedFieldName: "beacon_block".}: Web3SignerForkedBeaconBlock
      proofs*: Opt[seq[Web3SignerMerkleProof]]
    of Web3SignerRequestKind.Deposit:
      deposit*: Web3SignerDepositData
    of Web3SignerRequestKind.RandaoReveal:
      randaoReveal* {.
        serializedFieldName: "randao_reveal".}: Web3SignerRandaoRevealData
    of Web3SignerRequestKind.VoluntaryExit:
      voluntaryExit* {.
        serializedFieldName: "voluntary_exit".}: VoluntaryExit
    of Web3SignerRequestKind.SyncCommitteeMessage:
      syncCommitteeMessage* {.
        serializedFieldName: "sync_committee_message".}:
          Web3SignerSyncCommitteeMessageData
    of Web3SignerRequestKind.SyncCommitteeSelectionProof:
      syncAggregatorSelectionData* {.
        serializedFieldName: "sync_aggregator_selection_data".}:
          SyncAggregatorSelectionData
    of Web3SignerRequestKind.SyncCommitteeContributionAndProof:
      syncCommitteeContributionAndProof* {.
        serializedFieldName: "contribution_and_proof".}: ContributionAndProof
    of Web3SignerRequestKind.ValidatorRegistration:
      validatorRegistration* {.
        serializedFieldName: "validator_registration".}:
          Web3SignerValidatorRegistration

  GetBlockV2Response* = ForkedSignedBeaconBlock
  GetStateV2Response* = ref ForkedHashedBeaconState

  RestRoot* = object
    root*: Eth2Digest

  RestNimbusTimestamp1* = object
    timestamp1*: uint64

  RestNimbusTimestamp2* = object
    timestamp1*: uint64
    timestamp2*: uint64
    timestamp3*: uint64
    delay*: uint64

  RestBeaconCommitteeSelection* = object
    validator_index*: RestValidatorIndex
    slot*: Slot
    selection_proof*: ValidatorSig

  RestSyncCommitteeSelection* = object
    validator_index*: RestValidatorIndex
    slot*: Slot
    subcommittee_index*: uint64
    selection_proof*: ValidatorSig

  # Types based on the OAPI yaml file - used in responses to requests
  GetBeaconHeadResponse* = DataEnclosedObject[Slot]
  GetAggregatedAttestationResponse* = DataEnclosedObject[Attestation]
  GetAttesterDutiesResponse* = DataRootEnclosedObject[seq[RestAttesterDuty]]
  GetBlockAttestationsResponse* = DataEnclosedObject[seq[Attestation]]
  GetBlockHeaderResponse* = DataOptimisticAndFinalizedObject[RestBlockHeaderInfo]
  GetBlockHeadersResponse* = DataEnclosedObject[seq[RestBlockHeaderInfo]]
  GetBlockRootResponse* = DataOptimisticObject[RestRoot]
  GetDebugChainHeadsResponse* = DataEnclosedObject[seq[RestChainHead]]
  GetDepositContractResponse* = DataEnclosedObject[RestDepositContract]
  GetDepositSnapshotResponse* = DataEnclosedObject[RestDepositSnapshot]
  GetEpochCommitteesResponse* = DataEnclosedObject[seq[RestBeaconStatesCommittees]]
  GetForkScheduleResponse* = DataEnclosedObject[seq[Fork]]
  GetGenesisResponse* = DataEnclosedObject[RestGenesis]
  GetHeaderResponseCapella* = DataVersionEnclosedObject[capella_mev.SignedBuilderBid]
  GetHeaderResponseDeneb* = DataVersionEnclosedObject[deneb_mev.SignedBuilderBid]
  GetNetworkIdentityResponse* = DataEnclosedObject[RestNetworkIdentity]
  GetPeerCountResponse* = DataMetaEnclosedObject[RestPeerCount]
  GetPeerResponse* = DataMetaEnclosedObject[RestNodePeer]
  GetPeersResponse* = DataMetaEnclosedObject[seq[RestNodePeer]]
  GetPoolAttestationsResponse* = DataEnclosedObject[seq[Attestation]]
  GetPoolAttesterSlashingsResponse* = DataEnclosedObject[seq[AttesterSlashing]]
  GetPoolProposerSlashingsResponse* = DataEnclosedObject[seq[ProposerSlashing]]
  GetPoolVoluntaryExitsResponse* = DataEnclosedObject[seq[SignedVoluntaryExit]]
  GetProposerDutiesResponse* = DataRootEnclosedObject[seq[RestProposerDuty]]
  GetSpecVCResponse* = DataEnclosedObject[VCRuntimeConfig]
  GetStateFinalityCheckpointsResponse* = DataEnclosedObject[RestBeaconStatesFinalityCheckpoints]
  GetStateForkResponse* = DataEnclosedObject[Fork]
  GetStateRootResponse* = DataOptimisticObject[RestRoot]
  GetStateValidatorBalancesResponse* = DataEnclosedObject[seq[RestValidatorBalance]]
  GetStateValidatorResponse* = DataEnclosedObject[RestValidator]
  GetStateValidatorsResponse* = DataOptimisticObject[seq[RestValidator]]
  GetStateRandaoResponse* = DataOptimisticObject[RestEpochRandao]
  GetNextWithdrawalsResponse* = DataOptimisticObject[seq[Withdrawal]]
  GetSyncCommitteeDutiesResponse* = DataOptimisticObject[seq[RestSyncCommitteeDuty]]
  GetSyncingStatusResponse* = DataEnclosedObject[RestSyncInfo]
  GetVersionResponse* = DataEnclosedObject[RestNodeVersion]
  GetEpochSyncCommitteesResponse* = DataEnclosedObject[RestEpochSyncCommittee]
  ProduceAttestationDataResponse* = DataEnclosedObject[AttestationData]
  ProduceBlindedBlockResponse* = ForkedBlindedBeaconBlock
  ProduceSyncCommitteeContributionResponse* = DataEnclosedObject[SyncCommitteeContribution]
  SubmitBlindedBlockResponseCapella* = DataEnclosedObject[capella.ExecutionPayload]
  SubmitBlindedBlockResponseDeneb* = DataEnclosedObject[deneb_mev.ExecutionPayloadAndBlobsBundle]
  GetValidatorsActivityResponse* = DataEnclosedObject[seq[RestActivityItem]]
  GetValidatorsLivenessResponse* = DataEnclosedObject[seq[RestLivenessItem]]
  SubmitBeaconCommitteeSelectionsResponse* = DataEnclosedObject[seq[RestBeaconCommitteeSelection]]
  SubmitSyncCommitteeSelectionsResponse* = DataEnclosedObject[seq[RestSyncCommitteeSelection]]

  RestNodeValidity* {.pure.} = enum
    valid = "VALID",
    invalid = "INVALID",
    optimistic = "OPTIMISTIC"

  RestNodeExtraData* = object
    justified_root*: Eth2Digest
    finalized_root*: Eth2Digest
    u_justified_checkpoint*: Option[Checkpoint]
    u_finalized_checkpoint*: Option[Checkpoint]
    best_child*: Eth2Digest
    best_descendant*: Eth2Digest

  RestNode* = object
    slot*: Slot
    block_root*: Eth2Digest
    parent_root*: Eth2Digest
    justified_epoch*: Epoch
    finalized_epoch*: Epoch
    weight*: uint64
    validity*: RestNodeValidity
    execution_block_hash*: Eth2Digest
    extra_data*: Option[RestNodeExtraData]

  RestExtraData* = object
    version*: Option[string]

  GetForkChoiceResponse* = object
    justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint
    fork_choice_nodes*: seq[RestNode]
    extra_data*: RestExtraData

func `==`*(a, b: RestValidatorIndex): bool =
  uint64(a) == uint64(b)

func init*(T: type ForkedSignedBeaconBlock,
           contents: RestPublishedSignedBlockContents): T =
  return
    case contents.kind
    of ConsensusFork.Phase0:
      ForkedSignedBeaconBlock.init(contents.phase0Data)
    of ConsensusFork.Altair:
      ForkedSignedBeaconBlock.init(contents.altairData)
    of ConsensusFork.Bellatrix:
      ForkedSignedBeaconBlock.init(contents.bellatrixData)
    of ConsensusFork.Capella:
      ForkedSignedBeaconBlock.init(contents.capellaData)
    of ConsensusFork.Deneb:
      ForkedSignedBeaconBlock.init(contents.denebData.signed_block)

func init*(t: typedesc[StateIdent], v: StateIdentType): StateIdent =
  StateIdent(kind: StateQueryKind.Named, value: v)

func init*(t: typedesc[StateIdent], v: Slot): StateIdent =
  StateIdent(kind: StateQueryKind.Slot, slot: v)

func init*(t: typedesc[StateIdent], v: Eth2Digest): StateIdent =
  StateIdent(kind: StateQueryKind.Root, root: v)

func init*(t: typedesc[BlockIdent], v: BlockIdentType): BlockIdent =
  BlockIdent(kind: BlockQueryKind.Named, value: v)

func init*(t: typedesc[BlockIdent], v: Slot): BlockIdent =
  BlockIdent(kind: BlockQueryKind.Slot, slot: v)

func init*(t: typedesc[BlockIdent], v: Eth2Digest): BlockIdent =
  BlockIdent(kind: BlockQueryKind.Root, root: v)

func init*(t: typedesc[ValidatorIdent], v: ValidatorIndex): ValidatorIdent =
  ValidatorIdent(kind: ValidatorQueryKind.Index, index: RestValidatorIndex(v))

func init*(t: typedesc[ValidatorIdent], v: ValidatorPubKey): ValidatorIdent =
  ValidatorIdent(kind: ValidatorQueryKind.Key, key: v)

func init*(t: typedesc[RestBlockInfo],
           v: ForkedTrustedSignedBeaconBlock): RestBlockInfo =
  withBlck(v):
    RestBlockInfo(slot: forkyBlck.message.slot, blck: forkyBlck.root)

func init*(t: typedesc[RestValidator], index: ValidatorIndex,
           balance: uint64, status: string,
           validator: Validator): RestValidator =
  RestValidator(index: index, balance: Base10.toString(balance),
                status: status, validator: validator)

func init*(t: typedesc[RestValidatorBalance], index: ValidatorIndex,
           balance: uint64): RestValidatorBalance =
  RestValidatorBalance(index: index, balance: Base10.toString(balance))

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: Slot,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.AggregationSlot,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    aggregationSlot: Web3SignerAggregationSlotData(slot: data)
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: AggregateAndProof,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.AggregateAndProof,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    aggregateAndProof: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: AttestationData,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.Attestation,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    attestation: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest,
           data: Web3SignerForkedBeaconBlock,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.BlockV2,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    beaconBlockHeader: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest,
           data: Web3SignerForkedBeaconBlock,
           proofs: openArray[Web3SignerMerkleProof],
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.BlockV2,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    proofs: Opt.some(@proofs),
    beaconBlockHeader: data
  )

func init*(t: typedesc[Web3SignerRequest], genesisForkVersion: Version,
           data: DepositMessage,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.Deposit,
    signingRoot: signingRoot,
    deposit: Web3SignerDepositData(
      pubkey: data.pubkey,
      withdrawalCredentials: data.withdrawal_credentials,
      genesisForkVersion: genesisForkVersion,
      amount: data.amount
    )
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: Epoch,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.RandaoReveal,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    randaoReveal: Web3SignerRandaoRevealData(epoch: data)
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: VoluntaryExit,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.VoluntaryExit,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    voluntaryExit: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, blockRoot: Eth2Digest,
           slot: Slot, signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.SyncCommitteeMessage,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    syncCommitteeMessage: Web3SignerSyncCommitteeMessageData(
      beaconBlockRoot: blockRoot, slot: slot
    )
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest,
           data: SyncAggregatorSelectionData,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.SyncCommitteeSelectionProof,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    syncAggregatorSelectionData: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest,
           data: ContributionAndProof,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.SyncCommitteeContributionAndProof,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    syncCommitteeContributionAndProof: data
  )

from stew/byteutils import to0xHex

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest,
           data: ValidatorRegistrationV1,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.ValidatorRegistration,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    validatorRegistration: Web3SignerValidatorRegistration(
      feeRecipient: data.fee_recipient.data.to0xHex,
      gasLimit: data.gas_limit,
      timestamp: data.timestamp,
      pubkey: data.pubkey)
  )

func init*(t: typedesc[RestSyncCommitteeMessage],
           slot: Slot,
           beacon_block_root: Eth2Digest,
           validator_index: uint64,
           signature: ValidatorSig): RestSyncCommitteeMessage =
  RestSyncCommitteeMessage(
    slot: slot,
    beacon_block_root: beacon_block_root,
    validator_index: validator_index,
    signature: signature
  )

func init*(t: typedesc[RestSyncCommitteeContribution],
           slot: Slot,
           beacon_block_root: Eth2Digest,
           subcommittee_index: uint64,
           aggregation_bits: SyncCommitteeAggregationBits,
           signature: ValidatorSig): RestSyncCommitteeContribution =
  RestSyncCommitteeContribution(
    slot: slot,
    beacon_block_root: beacon_block_root,
    subcommittee_index: subcommittee_index,
    aggregation_bits: aggregation_bits,
    signature: signature)

func init*(t: typedesc[RestContributionAndProof],
           aggregator_index: uint64,
           selection_proof: ValidatorSig,
           contribution: SyncCommitteeContribution): RestContributionAndProof =
  RestContributionAndProof(
    aggregator_index: aggregator_index,
    selection_proof: selection_proof,
    contribution: RestSyncCommitteeContribution.init(
      contribution.slot,
      contribution.beacon_block_root,
      contribution.subcommittee_index,
      contribution.aggregation_bits,
      contribution.signature
    ))

func init*(t: typedesc[RestSignedContributionAndProof],
           message: ContributionAndProof,
           signature: ValidatorSig): RestSignedContributionAndProof =
  RestSignedContributionAndProof(
    message: RestContributionAndProof.init(
      message.aggregator_index,
      message.selection_proof,
      message.contribution
    ),
    signature: signature)

func len*(p: RestWithdrawalPrefix): int = sizeof(p)

func init*(t: typedesc[RestErrorMessage], code: int,
           message: string): RestErrorMessage =
  RestErrorMessage(code: code, message: message)

func init*(t: typedesc[RestErrorMessage], code: int,
           message: string, stacktrace: string): RestErrorMessage =
  RestErrorMessage(code: code, message: message,
                   stacktraces: Opt.some(@[stacktrace]))

func init*(t: typedesc[RestErrorMessage], code: int,
           message: string, stacktrace: openArray[string]): RestErrorMessage =
  RestErrorMessage(code: code, message: message,
                   stacktraces: Opt.some(@stacktrace))

func init*(t: typedesc[RestErrorMessage], code: HttpCode,
           message: string): RestErrorMessage =
  RestErrorMessage(code: code.toInt(), message: message)

func init*(t: typedesc[RestErrorMessage], code: HttpCode,
           message: string, stacktrace: string): RestErrorMessage =
  RestErrorMessage(code: code.toInt(), message: message,
                   stacktraces: Opt.some(@[stacktrace]))

func init*(t: typedesc[RestErrorMessage], code: HttpCode,
           message: string, stacktrace: openArray[string]): RestErrorMessage =
  RestErrorMessage(code: code.toInt(), message: message,
                   stacktraces: Opt.some(@stacktrace))

func toValidatorIndex*(value: RestValidatorIndex): Result[ValidatorIndex,
                                                          ValidatorIndexError] =
  when sizeof(ValidatorIndex) == 4:
    if uint64(value) < VALIDATOR_REGISTRY_LIMIT:
      # On x86 platform Nim allows only `int32` indexes, so all the indexes in
      # range `2^31 <= x < 2^32` are not supported.
      if uint64(value) <= uint64(high(int32)):
        ok(ValidatorIndex(value))
      else:
        err(ValidatorIndexError.UnsupportedValue)
    else:
      err(ValidatorIndexError.TooHighValue)
  elif sizeof(ValidatorIndex) == 8:
    if uint64(value) < VALIDATOR_REGISTRY_LIMIT:
      ok(ValidatorIndex(value))
    else:
      err(ValidatorIndexError.TooHighValue)
  else:
    doAssert(false, "ValidatorIndex type size is incorrect")

template withBlck*(x: ProduceBlockResponseV2,
                   body: untyped): untyped =
  case x.kind
  of ConsensusFork.Phase0:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    template blck: untyped {.inject.} = x.phase0Data
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    template blck: untyped {.inject.} = x.altairData
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    template blck: untyped {.inject.} = x.bellatrixData
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template blck: untyped {.inject.} = x.capellaData
    body
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template blck: untyped {.inject.} = x.denebData.blck
    body
