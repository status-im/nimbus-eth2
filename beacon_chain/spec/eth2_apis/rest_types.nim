# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Types used by both client and server in the common REST API:
# https://ethereum.github.io/beacon-APIs/
# Be mindful that changing these changes the serialization and deserialization
# in the API which may lead to incompatibilities between clients - tread
# carefully!

import
  std/[json, tables],
  results,
  stew/base10, httputils, stew/bitops2,
  ../forks

export forks, tables, httputils, results

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
  LowestScoreAggregatedAttestation* =
    phase0.Attestation(
      aggregation_bits: CommitteeValidatorsBits(BitSeq.init(1)))
  LowestScoreAggregatedElectraAttestation* =
    electra.Attestation(
      aggregation_bits: ElectraCommitteeValidatorsBits(BitSeq.init(1)))

static:
  doAssert(ClientMaximumValidatorIds <= ServerMaximumValidatorIds)

type
  # https://github.com/ethereum/beacon-APIs/blob/v2.4.2/apis/eventstream/index.yaml
  EventTopic* {.pure.} = enum
    Head, Block, BlockGossip, VoluntaryExit, BLSToExecutionChange,
    ProposerSlashing, AttesterSlashing, BlobSidecar, DataColumnSidecar, SingleAttestation,
    FinalizedCheckpoint, ChainReorg, ContributionAndProof,
    LightClientFinalityUpdate, LightClientOptimisticUpdate, ExecutionPayloadAvailable,
    ExecutionPayloadBid, PayloadAttestationMessage


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

  RestValidatorIdentity* = object
    index*: ValidatorIndex
    pubkey*: ValidatorPubKey
    activation_epoch*: Epoch

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
    is_optimistic*: Opt[bool]
    el_offline*: Opt[bool]

  RestPeerCount* = object
    disconnected*: uint64
    connecting*: uint64
    connected*: uint64
    disconnecting*: uint64

  RestChainHeadV2* = object
    root*: Eth2Digest
    slot*: Slot
    execution_optimistic*: bool

  RestMetadata* = object
    seq_number*: string
    syncnets*: string
    attnets*: string
    custody_group_count*: string

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

  PrepareBeaconProposer* = object
    validator_index*: ValidatorIndex
    fee_recipient*: Eth1Address

  DenebSignedBlockContents* = object
    signed_block*: deneb.SignedBeaconBlock
    kzg_proofs*: deneb.KzgProofs
    blobs*: deneb.Blobs

  ElectraSignedBlockContents* = object
    signed_block*: electra.SignedBeaconBlock
    kzg_proofs*: deneb.KzgProofs
    blobs*: deneb.Blobs

  FuluSignedBlockContents* = object
    signed_block*: fulu.SignedBeaconBlock
    kzg_proofs*: fulu.KzgProofs
    blobs*: deneb.Blobs

  GloasSignedBlockContents* = object
    signed_block*: gloas.SignedBeaconBlock
    kzg_proofs*: fulu.KzgProofs
    blobs*: deneb.Blobs

  HezeSignedBlockContents* = object
    signed_block*: heze.SignedBeaconBlock
    kzg_proofs*: fulu.KzgProofs
    blobs*: deneb.Blobs

  RestPublishedSignedBlockContents* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Data*:    phase0.SignedBeaconBlock
    of ConsensusFork.Altair:    altairData*:    altair.SignedBeaconBlock
    of ConsensusFork.Bellatrix: bellatrixData*: bellatrix.SignedBeaconBlock
    of ConsensusFork.Capella:   capellaData*:   capella.SignedBeaconBlock
    of ConsensusFork.Deneb:     denebData*:     DenebSignedBlockContents
    of ConsensusFork.Electra:   electraData*:   ElectraSignedBlockContents
    of ConsensusFork.Fulu:      fuluData*:      FuluSignedBlockContents
    of ConsensusFork.Gloas:     gloasData*:     GloasSignedBlockContents

  ProduceBlockResponseV3* = ForkedMaybeBlindedBeaconBlock

  VCRuntimeConfig* = Table[string, string]

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
    execution_optimistic*: Opt[bool]

  DataOptimisticObject*[T] = object
    data*: T
    execution_optimistic*: Opt[bool]

  DataOptimisticAndFinalizedObject*[T] = object
    data*: T
    execution_optimistic*: Opt[bool]
    finalized*: Opt[bool]

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
    fee_recipient*: Eth1Address
    gas_limit*: uint64
    timestamp*: uint64
    pubkey*: ValidatorPubKey

  Web3SignerMerkleProof* = object
    index*: GeneralizedIndex
    proof*: seq[Eth2Digest]

  # https://github.com/ethereum/remote-signing-api/blob/87a392deb4e43209ca896dde6b4ec40bef7ee02c/signing/paths/sign.yaml#L37
  Web3SignerRequestKind* {.pure.} = enum
    AggregationSlot = "AGGREGATION_SLOT"
    AggregateAndProof = "AGGREGATE_AND_PROOF"
    AggregateAndProofV2 = "AGGREGATE_AND_PROOF_V2"
    Attestation = "ATTESTATION"
    BlockV2 = "BLOCK_V2"
    Deposit = "DEPOSIT"
    RandaoReveal = "RANDAO_REVEAL"
    VoluntaryExit = "VOLUNTARY_EXIT"
    SyncCommitteeMessage = "SYNC_COMMITTEE_MESSAGE",
    SyncCommitteeSelectionProof = "SYNC_COMMITTEE_SELECTION_PROOF"
    SyncCommitteeContributionAndProof = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
    ValidatorRegistration = "VALIDATOR_REGISTRATION"

  Web3SignerRequest* = object
    signingRoot*: Opt[Eth2Digest]
    forkInfo* {.serializedFieldName: "fork_info".}: Opt[Web3SignerForkInfo]
    case kind* {.dontSerialize.}: Web3SignerRequestKind
    of Web3SignerRequestKind.AggregationSlot:
      aggregationSlot* {.
        serializedFieldName: "aggregation_slot".}: Web3SignerAggregationSlotData
    of Web3SignerRequestKind.AggregateAndProof:
      aggregateAndProof* {.
        serializedFieldName: "aggregate_and_proof".}: phase0.AggregateAndProof
    of Web3SignerRequestKind.AggregateAndProofV2:
      forkedAggregateAndProof* {.
        serializedFieldName: "aggregate_and_proof".}: ForkedAggregateAndProof
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
  GetAggregatedAttestationV2Response* = ForkedAttestation

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

  RestReward* = distinct int64

  RestSyncCommitteeReward* = object
    validator_index*: RestValidatorIndex
    reward*: RestReward

  # Types based on the OAPI yaml file - used in responses to requests
  GetBeaconHeadResponse* = DataEnclosedObject[Slot]
  GetAggregatedAttestationResponse* = DataEnclosedObject[phase0.Attestation]
  GetAttesterDutiesResponse* = DataRootEnclosedObject[seq[RestAttesterDuty]]
  GetBlockAttestationsResponse* = DataEnclosedObject[seq[phase0.Attestation]]
  GetBlockHeaderResponse* = DataOptimisticAndFinalizedObject[RestBlockHeaderInfo]
  GetBlockHeadersResponse* = DataEnclosedObject[seq[RestBlockHeaderInfo]]
  GetBlockRootResponse* = DataOptimisticObject[RestRoot]
  GetDebugChainHeadsV2Response* = DataEnclosedObject[seq[RestChainHeadV2]]
  GetEpochCommitteesResponse* = DataEnclosedObject[seq[RestBeaconStatesCommittees]]
  GetForkScheduleResponse* = DataEnclosedObject[seq[Fork]]
  GetGenesisResponse* = DataEnclosedObject[RestGenesis]
  GetNetworkIdentityResponse* = DataEnclosedObject[RestNetworkIdentity]
  GetPeerCountResponse* = DataMetaEnclosedObject[RestPeerCount]
  GetPeerResponse* = DataMetaEnclosedObject[RestNodePeer]
  GetPeersResponse* = DataMetaEnclosedObject[seq[RestNodePeer]]
  GetPoolAttestationsResponse* = DataEnclosedObject[seq[phase0.Attestation]]
  GetPoolAttesterSlashingsResponse* =
    DataEnclosedObject[seq[phase0.AttesterSlashing]]
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
  ProduceSyncCommitteeContributionResponse* = DataEnclosedObject[SyncCommitteeContribution]
  GetValidatorsActivityResponse* = DataEnclosedObject[seq[RestActivityItem]]
  GetValidatorsLivenessResponse* = DataEnclosedObject[seq[RestLivenessItem]]
  SubmitBeaconCommitteeSelectionsResponse* = DataEnclosedObject[seq[RestBeaconCommitteeSelection]]
  SubmitSyncCommitteeSelectionsResponse* = DataEnclosedObject[seq[RestSyncCommitteeSelection]]

  GetHeaderResponseElectra* = DataVersionEnclosedObject[electra_mev.SignedBuilderBid]
  GetHeaderResponseFulu* = DataVersionEnclosedObject[fulu_mev.SignedBuilderBid]
  SubmitBlindedBlockResponseElectra* = DataVersionEnclosedObject[electra_mev.ExecutionPayloadAndBlobsBundle]

  RestNodeValidity* {.pure.} = enum
    valid = "VALID",
    invalid = "INVALID",
    optimistic = "OPTIMISTIC"

  RestNodeExtraData* = object
    justified_root*: Eth2Digest
    finalized_root*: Eth2Digest
    u_justified_checkpoint*: Opt[Checkpoint]
    u_finalized_checkpoint*: Opt[Checkpoint]
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
    extra_data*: Opt[RestNodeExtraData]

  RestExtraData* = object
    confirmed_root*: Eth2Digest
    current_epoch_observed_justified_checkpoint*: Checkpoint
    previous_epoch_greatest_unrealized_checkpoint*: Checkpoint
    previous_slot_head*, current_slot_head*: Eth2Digest

  GetForkChoiceResponse* = object
    justified_checkpoint*: Checkpoint
    finalized_checkpoint*: Checkpoint
    fork_choice_nodes*: seq[RestNode]
    extra_data*: RestExtraData

  EmptyBody* = object

func isLowestScoreAggregatedAttestation*(a: phase0.Attestation): bool =
  (a.data.slot == GENESIS_SLOT) and
  (a.data.index == 0'u64) and
  (a.data.source.epoch == GENESIS_EPOCH) and
  (a.data.target.epoch == GENESIS_EPOCH)

func isLowestScoreAggregatedAttestation*(a: ForkedAttestation): bool =
  withAttestation(a):
    (forkyAttestation.data.slot == GENESIS_SLOT) and
    (forkyAttestation.data.index == 0'u64) and
    (forkyAttestation.data.source.epoch == GENESIS_EPOCH) and
    (forkyAttestation.data.target.epoch == GENESIS_EPOCH)

func `==`*(a, b: RestValidatorIndex): bool {.borrow.}

template withForkyBlck*(
    x: RestPublishedSignedBlockContents, body: untyped): untyped =
  case x.kind
  of ConsensusFork.Gloas:
    const consensusFork {.inject, used.} = ConsensusFork.Gloas
    template forkyData: untyped {.inject, used.} = x.gloasData
    template forkyBlck: untyped {.inject, used.} = x.gloasData.signed_block
    template kzg_proofs: untyped {.inject, used.} = x.gloasData.kzg_proofs
    template blobs: untyped {.inject, used.} = x.gloasData.blobs
    body
  of ConsensusFork.Fulu:
    const consensusFork {.inject, used.} = ConsensusFork.Fulu
    template forkyData: untyped {.inject, used.} = x.fuluData
    template forkyBlck: untyped {.inject, used.} = x.fuluData.signed_block
    template kzg_proofs: untyped {.inject, used.} = x.fuluData.kzg_proofs
    template blobs: untyped {.inject, used.} = x.fuluData.blobs
    body
  of ConsensusFork.Electra:
    const consensusFork {.inject, used.} = ConsensusFork.Electra
    template forkyData: untyped {.inject, used.} = x.electraData
    template forkyBlck: untyped {.inject, used.} = x.electraData.signed_block
    template kzg_proofs: untyped {.inject, used.} = x.electraData.kzg_proofs
    template blobs: untyped {.inject, used.} = x.electraData.blobs
    body
  of ConsensusFork.Deneb:
    const consensusFork {.inject, used.} = ConsensusFork.Deneb
    template forkyData: untyped {.inject, used.} = x.denebData
    template forkyBlck: untyped {.inject, used.} = x.denebData.signed_block
    template kzg_proofs: untyped {.inject, used.} = x.denebData.kzg_proofs
    template blobs: untyped {.inject, used.} = x.denebData.blobs
    body
  of ConsensusFork.Capella:
    const consensusFork {.inject, used.} = ConsensusFork.Capella
    template forkyData: untyped {.inject, used.} = x.capellaData
    template forkyBlck: untyped {.inject, used.} = x.capellaData
    body
  of ConsensusFork.Bellatrix:
    const consensusFork {.inject, used.} = ConsensusFork.Bellatrix
    template forkyData: untyped {.inject, used.} = x.bellatrixData
    template forkyBlck: untyped {.inject, used.} = x.bellatrixData
    body
  of ConsensusFork.Altair:
    const consensusFork {.inject, used.} = ConsensusFork.Altair
    template forkyData: untyped {.inject, used.} = x.altairData
    template forkyBlck: untyped {.inject, used.} = x.altairData
    body
  of ConsensusFork.Phase0:
    const consensusFork {.inject, used.} = ConsensusFork.Phase0
    template forkyData: untyped {.inject, used.} = x.phase0Data
    template forkyBlck: untyped {.inject, used.} = x.phase0Data
    body

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
    of ConsensusFork.Electra:
      ForkedSignedBeaconBlock.init(contents.electraData.signed_block)
    of ConsensusFork.Fulu:
      ForkedSignedBeaconBlock.init(contents.fuluData.signed_block)
    of ConsensusFork.Gloas:
      ForkedSignedBeaconBlock.init(contents.gloasData.signed_block)

func init*(t: typedesc[RestPublishedSignedBlockContents],
           blck: phase0.BeaconBlock, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Phase0,
    phase0Data: phase0.SignedBeaconBlock(
      message: blck, root: root, signature: signature
    )
  )

func init*(t: typedesc[RestPublishedSignedBlockContents],
           blck: altair.BeaconBlock, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Altair,
    altairData: altair.SignedBeaconBlock(
      message: blck, root: root, signature: signature
    )
  )

func init*(t: typedesc[RestPublishedSignedBlockContents],
           blck: bellatrix.BeaconBlock, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Bellatrix,
    bellatrixData: bellatrix.SignedBeaconBlock(
      message: blck, root: root, signature: signature
    )
  )

func init*(t: typedesc[RestPublishedSignedBlockContents],
           blck: capella.BeaconBlock, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Capella,
    capellaData: capella.SignedBeaconBlock(
      message: blck, root: root, signature: signature
    )
  )

func init*(t: typedesc[RestPublishedSignedBlockContents],
           contents: deneb.BlockContents, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Deneb,
    denebData: DenebSignedBlockContents(
      signed_block: deneb.SignedBeaconBlock(
        message: contents.`block`,
        root: root,
        signature: signature
      ),
      kzg_proofs: contents.kzg_proofs,
      blobs: contents.blobs
    )
  )

func init*(t: typedesc[RestPublishedSignedBlockContents],
           contents: electra.BlockContents, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Electra,
    electraData: ElectraSignedBlockContents(
      signed_block: electra.SignedBeaconBlock(
        message: contents.`block`,
        root: root,
        signature: signature
      ),
      kzg_proofs: contents.kzg_proofs,
      blobs: contents.blobs
    )
  )

func init*(t: typedesc[RestPublishedSignedBlockContents],
           contents: fulu.BlockContents, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Fulu,
    fuluData: FuluSignedBlockContents(
      signed_block: fulu.SignedBeaconBlock(
        message: contents.`block`,
        root: root,
        signature: signature
      ),
      kzg_proofs: contents.kzg_proofs,
      blobs: contents.blobs
    )
  )

func init*(t: typedesc[RestPublishedSignedBlockContents],
           contents: gloas.BlockContents, root: Eth2Digest,
           signature: ValidatorSig): RestPublishedSignedBlockContents =
  RestPublishedSignedBlockContents(
    kind: ConsensusFork.Gloas,
    gloasData: GloasSignedBlockContents(
      signed_block: gloas.SignedBeaconBlock(
        message: contents.`block`,
        root: root,
        signature: signature
      ),
      kzg_proofs: contents.kzg_proofs,
      blobs: contents.blobs
    )
  )

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
           balance: Gwei, status: string,
           validator: Validator): RestValidator =
  RestValidator(index: index, balance: Base10.toString(balance),
                status: status, validator: validator)

func init*(t: typedesc[RestValidatorIdentity], index: ValidatorIndex,
           pubkey: ValidatorPubKey,
           activation_epoch: Epoch): RestValidatorIdentity =
  RestValidatorIdentity(index: index, pubkey: pubkey,
                        activation_epoch: activation_epoch)

func init*(t: typedesc[RestValidatorBalance], index: ValidatorIndex,
           balance: Gwei): RestValidatorBalance =
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
           genesis_validators_root: Eth2Digest, data: phase0.AggregateAndProof,
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

func init*(
    t: typedesc[Web3SignerRequest],
    fork: Fork,
    genesis_validators_root: Eth2Digest,
    data: electra.AggregateAndProof,
    signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.AggregateAndProofV2,
    forkInfo: Opt.some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    forkedAggregateAndProof:
      ForkedAggregateAndProof.init(data, typeof(data).kind)
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

func init*(t: typedesc[Web3SignerRequest],
           genesis_validators_root: Eth2Digest,
           data: ValidatorRegistrationV1,
           signingRoot: Opt[Eth2Digest] = Opt.none(Eth2Digest)
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.ValidatorRegistration,
    signingRoot: signingRoot,
    validatorRegistration: Web3SignerValidatorRegistration(
      fee_recipient: data.fee_recipient,
      gas_limit: data.gas_limit,
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

## Types and helpers for historical_summaries + proof endpoint
const
  # gIndex for historical_summaries field (27th field in BeaconState)
  HISTORICAL_SUMMARIES_GINDEX* = GeneralizedIndex(59) # 32 + 27 = 59
  HISTORICAL_SUMMARIES_GINDEX_ELECTRA* = GeneralizedIndex(91) # 64 + 27 = 91

type
  # Note: these could go in separate Capella/Electra spec files if they were
  # part of the specification.
  HistoricalSummariesProof* = array[log2trunc(HISTORICAL_SUMMARIES_GINDEX), Eth2Digest]
  HistoricalSummariesProofElectra* =
    array[log2trunc(HISTORICAL_SUMMARIES_GINDEX_ELECTRA), Eth2Digest]

  # REST API types
  GetHistoricalSummariesV1Response* = object
    historical_summaries*: HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]
    proof*: HistoricalSummariesProof
    slot*: Slot

  GetHistoricalSummariesV1ResponseElectra* = object
    historical_summaries*: HashList[HistoricalSummary, Limit HISTORICAL_ROOTS_LIMIT]
    proof*: HistoricalSummariesProofElectra
    slot*: Slot

  ForkyGetHistoricalSummariesV1Response* =
    GetHistoricalSummariesV1Response |
    GetHistoricalSummariesV1ResponseElectra

  HistoricalSummariesFork* {.pure.} = enum
    Capella = 0,
    Electra = 1

  # REST client response type
  ForkedHistoricalSummariesWithProof* = object
    case kind*: HistoricalSummariesFork
    of HistoricalSummariesFork.Capella: capellaData*: GetHistoricalSummariesV1Response
    of HistoricalSummariesFork.Electra: electraData*: GetHistoricalSummariesV1ResponseElectra

template historical_summaries_gindex*(
    kind: static HistoricalSummariesFork): GeneralizedIndex =
  case kind
  of HistoricalSummariesFork.Electra:
    HISTORICAL_SUMMARIES_GINDEX_ELECTRA
  of HistoricalSummariesFork.Capella:
    HISTORICAL_SUMMARIES_GINDEX

template getHistoricalSummariesResponse*(
    kind: static HistoricalSummariesFork): auto =
  when kind >= HistoricalSummariesFork.Electra:
    GetHistoricalSummariesV1ResponseElectra
  elif kind >= HistoricalSummariesFork.Capella:
    GetHistoricalSummariesV1Response

template init*(
    T: type ForkedHistoricalSummariesWithProof,
    historical_summaries: GetHistoricalSummariesV1Response,
): T =
    ForkedHistoricalSummariesWithProof(
      kind: HistoricalSummariesFork.Capella, capellaData: historical_summaries
    )

template init*(
    T: type ForkedHistoricalSummariesWithProof,
    historical_summaries: GetHistoricalSummariesV1ResponseElectra,
): T =
    ForkedHistoricalSummariesWithProof(
      kind: HistoricalSummariesFork.Electra, electraData: historical_summaries
    )

func historicalSummariesForkAtConsensusFork*(consensusFork: ConsensusFork): Opt[HistoricalSummariesFork] =
  static: doAssert HistoricalSummariesFork.high == HistoricalSummariesFork.Electra
  if consensusFork >= ConsensusFork.Electra:
    Opt.some HistoricalSummariesFork.Electra
  elif consensusFork >= ConsensusFork.Capella:
    Opt.some HistoricalSummariesFork.Capella
  else:
    Opt.none HistoricalSummariesFork

func parse*(_: type ValidatorIdent, value: string): Result[ValidatorIdent, cstring] =
  # Either key or index depending on prefix
  if len(value) > 2 and (value[0] == '0') and (value[1] == 'x'):
    let res = ? ValidatorPubKey.fromHex(value)
    ok(ValidatorIdent(kind: ValidatorQueryKind.Key, key: res))
  else:
    let res = RestValidatorIndex(? Base10.decode(uint64, value))
    ok(ValidatorIdent(kind: ValidatorQueryKind.Index, index: res))

func parse*(_: type ValidatorFilter, value: string): Result[ValidatorFilter, cstring] =
  case value
  of "pending_initialized":
    ok({ValidatorFilterKind.PendingInitialized})
  of "pending_queued":
    ok({ValidatorFilterKind.PendingQueued})
  of "active_ongoing":
    ok({ValidatorFilterKind.ActiveOngoing})
  of "active_exiting":
    ok({ValidatorFilterKind.ActiveExiting})
  of "active_slashed":
    ok({ValidatorFilterKind.ActiveSlashed})
  of "exited_unslashed":
    ok({ValidatorFilterKind.ExitedUnslashed})
  of "exited_slashed":
    ok({ValidatorFilterKind.ExitedSlashed})
  of "withdrawal_possible":
    ok({ValidatorFilterKind.WithdrawalPossible})
  of "withdrawal_done":
    ok({ValidatorFilterKind.WithdrawalDone})
  of "pending":
    ok({
      ValidatorFilterKind.PendingInitialized,
      ValidatorFilterKind.PendingQueued
    })
  of "active":
    ok({
      ValidatorFilterKind.ActiveOngoing,
      ValidatorFilterKind.ActiveExiting,
      ValidatorFilterKind.ActiveSlashed
    })
  of "exited":
    ok({
      ValidatorFilterKind.ExitedUnslashed,
      ValidatorFilterKind.ExitedSlashed
    })
  of "withdrawal":
    ok({
      ValidatorFilterKind.WithdrawalPossible,
      ValidatorFilterKind.WithdrawalDone
    })
  else:
    err("Incorrect validator state identifier value")

func toList*(value: set[ValidatorFilterKind]): seq[string] =
  const
    pendingSet = {ValidatorFilterKind.PendingInitialized,
                  ValidatorFilterKind.PendingQueued}
    activeSet = {ValidatorFilterKind.ActiveOngoing,
                 ValidatorFilterKind.ActiveExiting,
                 ValidatorFilterKind.ActiveSlashed}
    exitedSet = {ValidatorFilterKind.ExitedUnslashed,
                 ValidatorFilterKind.ExitedSlashed}
    withdrawSet = {ValidatorFilterKind.WithdrawalPossible,
                   ValidatorFilterKind.WithdrawalDone}
  var
    res: seq[string]
    v = value

  template processSet(argSet, argName: untyped): untyped =
    if argSet * v == argSet:
      res.add(argName)
      v.excl(argSet)

  template processSingle(argSingle, argName): untyped =
    if argSingle in v:
      res.add(argName)

  processSet(pendingSet, "pending")
  processSet(activeSet, "active")
  processSet(exitedSet, "exited")
  processSet(withdrawSet, "withdrawal")
  processSingle(ValidatorFilterKind.PendingInitialized, "pending_initialized")
  processSingle(ValidatorFilterKind.PendingQueued, "pending_queued")
  processSingle(ValidatorFilterKind.ActiveOngoing, "active_ongoing")
  processSingle(ValidatorFilterKind.ActiveExiting, "active_exiting")
  processSingle(ValidatorFilterKind.ActiveSlashed, "active_slashed")
  processSingle(ValidatorFilterKind.ExitedUnslashed, "exited_unslashed")
  processSingle(ValidatorFilterKind.ExitedSlashed, "exited_slashed")
  processSingle(ValidatorFilterKind.WithdrawalPossible, "withdrawal_possible")
  processSingle(ValidatorFilterKind.WithdrawalDone, "withdrawal_done")
  res
