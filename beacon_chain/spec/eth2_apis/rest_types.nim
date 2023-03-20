# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Types used by both client and server in the common REST API:
# https://ethereum.github.io/eth2.0-APIs/#/
# Be mindful that changing these changes the serialization and deserialization
# in the API which may lead to incompatibilities between clients - tread
# carefully!

{.push raises: [].}

import
  std/json,
  stew/base10, web3/ethtypes,
  ".."/forks,
  ".."/datatypes/[phase0, altair, bellatrix, deneb],
  ".."/mev/[bellatrix_mev, capella_mev]

from ".."/datatypes/capella import BeaconBlockBody

export forks, phase0, altair, bellatrix, capella, bellatrix_mev, capella_mev

const
  # https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/states/validator_balances.yaml#L17
  # https://github.com/ethereum/eth2.0-APIs/blob/master/apis/beacon/states/validators.yaml#L17
  # Maximum number of validators that can be served by the REST server in one
  # request, if the number of validator exceeds this value REST server
  # will return HTTP error 400.
  ServerMaximumValidatorIds* = 16384

  # Maximum number of validators that can be sent in single request by
  # validator client (VC).
  # NOTE: This value depend on beacon node's `rest-max-headers-size`
  # configuration option.
  #
  # Size of public key in HTTP request could be calculated by formula -
  # bytes48 * 2 + len("0x") + len(",") = 99 bytes.
  # So 1024 keys will occupy 101,376 bytes. Default value for HTTP headers size
  # is 128Kb = 131,072 bytes.
  ClientMaximumValidatorIds* = 1024

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
    ## https://github.com/ethereum/beacon-APIs/blob/v2.3.0/types/http.yaml#L86
    code*: int
    message*: string
    stacktraces*: Option[seq[string]]

  RestIndexedErrorMessage* = object
    ## https://github.com/ethereum/beacon-APIs/blob/v2.3.0/types/http.yaml#L101
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

  # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.2/specs/capella/beacon-chain.md#executionpayload
  RestExecutionPayload* = object
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
    base_fee_per_gas*: UInt256

    # Extra payload fields
    block_hash*: Eth2Digest # Hash of execution block
    transactions*: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]
    withdrawals*: Option[List[Withdrawal, MAX_WITHDRAWALS_PER_PAYLOAD]]  # [New in Capella]

  PrepareBeaconProposer* = object
    validator_index*: ValidatorIndex
    fee_recipient*: Eth1Address

  RestPublishedSignedBeaconBlock* = distinct ForkedSignedBeaconBlock

  RestPublishedBeaconBlock* = distinct ForkedBeaconBlock

  RestPublishedBeaconBlockBody* = object
    case kind*: ConsensusFork
    of ConsensusFork.Phase0:    phase0Body*:    phase0.BeaconBlockBody
    of ConsensusFork.Altair:    altairBody*:    altair.BeaconBlockBody
    of ConsensusFork.Bellatrix: bellatrixBody*: bellatrix.BeaconBlockBody
    of ConsensusFork.Capella:   capellaBody*:   capella.BeaconBlockBody
    of ConsensusFork.Deneb:     denebBody*:     deneb.BeaconBlockBody

  RestSpec* = object
    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.3/presets/mainnet/phase0.yaml
    MAX_COMMITTEES_PER_SLOT*: uint64
    TARGET_COMMITTEE_SIZE*: uint64
    MAX_VALIDATORS_PER_COMMITTEE*: uint64
    SHUFFLE_ROUND_COUNT*: uint64
    HYSTERESIS_QUOTIENT*: uint64
    HYSTERESIS_DOWNWARD_MULTIPLIER*: uint64
    HYSTERESIS_UPWARD_MULTIPLIER*: uint64
    SAFE_SLOTS_TO_UPDATE_JUSTIFIED*: uint64
    MIN_DEPOSIT_AMOUNT*: uint64
    MAX_EFFECTIVE_BALANCE*: uint64
    EFFECTIVE_BALANCE_INCREMENT*: uint64
    MIN_ATTESTATION_INCLUSION_DELAY*: uint64
    SLOTS_PER_EPOCH*: uint64
    MIN_SEED_LOOKAHEAD*: uint64
    MAX_SEED_LOOKAHEAD*: uint64
    EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64
    SLOTS_PER_HISTORICAL_ROOT*: uint64
    MIN_EPOCHS_TO_INACTIVITY_PENALTY*: uint64
    EPOCHS_PER_HISTORICAL_VECTOR*: uint64
    EPOCHS_PER_SLASHINGS_VECTOR*: uint64
    HISTORICAL_ROOTS_LIMIT*: uint64
    VALIDATOR_REGISTRY_LIMIT*: uint64
    BASE_REWARD_FACTOR*: uint64
    WHISTLEBLOWER_REWARD_QUOTIENT*: uint64
    PROPOSER_REWARD_QUOTIENT*: uint64
    INACTIVITY_PENALTY_QUOTIENT*: uint64
    MIN_SLASHING_PENALTY_QUOTIENT*: uint64
    PROPORTIONAL_SLASHING_MULTIPLIER*: uint64
    MAX_PROPOSER_SLASHINGS*: uint64
    MAX_ATTESTER_SLASHINGS*: uint64
    MAX_ATTESTATIONS*: uint64
    MAX_DEPOSITS*: uint64
    MAX_VOLUNTARY_EXITS*: uint64

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/presets/mainnet/altair.yaml
    INACTIVITY_PENALTY_QUOTIENT_ALTAIR*: uint64
    MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR*: uint64
    PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR*: uint64
    SYNC_COMMITTEE_SIZE*: uint64
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD*: uint64
    MIN_SYNC_COMMITTEE_PARTICIPANTS*: uint64
    UPDATE_TIMEOUT*: uint64

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/presets/mainnet/bellatrix.yaml
    INACTIVITY_PENALTY_QUOTIENT_BELLATRIX*: uint64
    MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX*: uint64
    PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX*: uint64
    MAX_BYTES_PER_TRANSACTION*: uint64
    MAX_TRANSACTIONS_PER_PAYLOAD*: uint64
    BYTES_PER_LOGS_BLOOM*: uint64
    MAX_EXTRA_DATA_BYTES*: uint64

    # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/configs/mainnet.yaml
    PRESET_BASE*: string
    CONFIG_NAME*: string
    TERMINAL_TOTAL_DIFFICULTY*: UInt256
    TERMINAL_BLOCK_HASH*: BlockHash
    TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH*: uint64
    MIN_GENESIS_ACTIVE_VALIDATOR_COUNT*: uint64
    MIN_GENESIS_TIME*: uint64
    GENESIS_FORK_VERSION*: Version
    GENESIS_DELAY*: uint64
    ALTAIR_FORK_VERSION*: Version
    ALTAIR_FORK_EPOCH*: uint64
    BELLATRIX_FORK_VERSION*: Version
    BELLATRIX_FORK_EPOCH*: uint64
    CAPELLA_FORK_VERSION*: Version
    CAPELLA_FORK_EPOCH*: uint64
    DENEB_FORK_VERSION*: Version
    DENEB_FORK_EPOCH*: uint64
    SECONDS_PER_SLOT*: uint64
    SECONDS_PER_ETH1_BLOCK*: uint64
    MIN_VALIDATOR_WITHDRAWABILITY_DELAY*: uint64
    SHARD_COMMITTEE_PERIOD*: uint64
    ETH1_FOLLOW_DISTANCE*: uint64
    INACTIVITY_SCORE_BIAS*: uint64
    INACTIVITY_SCORE_RECOVERY_RATE*: uint64
    EJECTION_BALANCE*: uint64
    MIN_PER_EPOCH_CHURN_LIMIT*: uint64
    CHURN_LIMIT_QUOTIENT*: uint64
    PROPOSER_SCORE_BOOST*: uint64
    DEPOSIT_CHAIN_ID*: uint64
    DEPOSIT_NETWORK_ID*: uint64
    DEPOSIT_CONTRACT_ADDRESS*: Eth1Address

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.3/specs/phase0/beacon-chain.md#constants
    # GENESIS_SLOT
    # GENESIS_EPOCH
    # FAR_FUTURE_EPOCH
    # BASE_REWARDS_PER_EPOCH
    # DEPOSIT_CONTRACT_TREE_DEPTH
    # JUSTIFICATION_BITS_LENGTH
    # ENDIANNESS
    BLS_WITHDRAWAL_PREFIX*: byte
    ETH1_ADDRESS_WITHDRAWAL_PREFIX*: byte
    DOMAIN_BEACON_PROPOSER*: DomainType
    DOMAIN_BEACON_ATTESTER*: DomainType
    DOMAIN_RANDAO*: DomainType
    DOMAIN_DEPOSIT*: DomainType
    DOMAIN_VOLUNTARY_EXIT*: DomainType
    DOMAIN_SELECTION_PROOF*: DomainType
    DOMAIN_AGGREGATE_AND_PROOF*: DomainType

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.3/specs/altair/beacon-chain.md#constants
    TIMELY_SOURCE_FLAG_INDEX*: byte
    TIMELY_TARGET_FLAG_INDEX*: byte
    TIMELY_HEAD_FLAG_INDEX*: byte
    TIMELY_SOURCE_WEIGHT*: uint64
    TIMELY_TARGET_WEIGHT*: uint64
    TIMELY_HEAD_WEIGHT*: uint64
    SYNC_REWARD_WEIGHT*: uint64
    PROPOSER_WEIGHT*: uint64
    WEIGHT_DENOMINATOR*: uint64
    DOMAIN_SYNC_COMMITTEE*: DomainType
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF*: DomainType
    DOMAIN_CONTRIBUTION_AND_PROOF*: DomainType
    # PARTICIPATION_FLAG_WEIGHTS

    # https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/specs/phase0/validator.md#constants
    TARGET_AGGREGATORS_PER_COMMITTEE*: uint64
    RANDOM_SUBNETS_PER_VALIDATOR*: uint64
    EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION*: uint64
    ATTESTATION_SUBNET_COUNT*: uint64

    # https://github.com/ethereum/consensus-specs/blob/v1.2.0/specs/altair/validator.md#constants
    TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE*: uint64
    SYNC_COMMITTEE_SUBNET_COUNT*: uint64

  # The `RestSpec` is a dynamic dictionary that includes version-specific spec
  # constants. New versions may introduce new constants, and remove old ones.
  # The Nimbus validator client fetches the remote spec to determine whether it
  # is connected to a compatible beacon node. For this purpose, it only needs to
  # verify a small set of relevant spec constants. To avoid rejecting a remote
  # spec that includes all of those relevant spec constants, but that does not
  # include all of the locally known spec constants, a separate type is defined
  # that includes just the spec constants relevant for the validator client.
  # Extra spec constants are silently ignored.
  RestSpecVC* = object
    # /!\ Keep in sync with `validator_client/api.nim` > `checkCompatible`.
    MAX_VALIDATORS_PER_COMMITTEE*: uint64
    SLOTS_PER_EPOCH*: uint64
    SECONDS_PER_SLOT*: uint64
    EPOCHS_PER_ETH1_VOTING_PERIOD*: uint64
    SLOTS_PER_HISTORICAL_ROOT*: uint64
    EPOCHS_PER_HISTORICAL_VECTOR*: uint64
    EPOCHS_PER_SLASHINGS_VECTOR*: uint64
    HISTORICAL_ROOTS_LIMIT*: uint64
    VALIDATOR_REGISTRY_LIMIT*: uint64
    MAX_PROPOSER_SLASHINGS*: uint64
    MAX_ATTESTER_SLASHINGS*: uint64
    MAX_ATTESTATIONS*: uint64
    MAX_DEPOSITS*: uint64
    MAX_VOLUNTARY_EXITS*: uint64
    DOMAIN_BEACON_PROPOSER*: DomainType
    DOMAIN_BEACON_ATTESTER*: DomainType
    DOMAIN_RANDAO*: DomainType
    DOMAIN_DEPOSIT*: DomainType
    DOMAIN_VOLUNTARY_EXIT*: DomainType
    DOMAIN_SELECTION_PROOF*: DomainType
    DOMAIN_AGGREGATE_AND_PROOF*: DomainType

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

  ForkedSignedBlockHeader* = object
    message*: uint32 # message offset
    signature*: ValidatorSig
    slot*: Slot

  Web3SignerKeysResponse* = object
    keys*: seq[ValidatorPubKey]

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

  Web3SignerRequestKind* {.pure.} = enum
    AggregationSlot, AggregateAndProof, Attestation, Block, BlockV2,
    Deposit, RandaoReveal, VoluntaryExit, SyncCommitteeMessage,
    SyncCommitteeSelectionProof, SyncCommitteeContributionAndProof,
    ValidatorRegistration

  Web3SignerRequest* = object
    signingRoot*: Option[Eth2Digest]
    forkInfo* {.serializedFieldName: "fork_info".}: Option[Web3SignerForkInfo]
    case kind* {.dontSerialize.}: Web3SignerRequestKind
    of Web3SignerRequestKind.AggregationSlot:
      aggregationSlot* {.
        serializedFieldName: "aggregation_slot".}: Web3SignerAggregationSlotData
    of Web3SignerRequestKind.AggregateAndProof:
      aggregateAndProof* {.
        serializedFieldName: "aggregate_and_proof".}: AggregateAndProof
    of Web3SignerRequestKind.Attestation:
      attestation*: AttestationData
    of Web3SignerRequestKind.Block:
      blck* {.
        serializedFieldName: "block".}: phase0.BeaconBlock
    of Web3SignerRequestKind.BlockV2:
      beaconBlock* {.
        serializedFieldName: "beacon_block".}: Web3SignerForkedBeaconBlock
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

  # Types based on the OAPI yaml file - used in responses to requests
  GetBeaconHeadResponse* = DataEnclosedObject[Slot]
  GetAggregatedAttestationResponse* = DataEnclosedObject[Attestation]
  GetAttesterDutiesResponse* = DataRootEnclosedObject[seq[RestAttesterDuty]]
  GetBlockAttestationsResponse* = DataEnclosedObject[seq[Attestation]]
  GetBlockHeaderResponse* = DataEnclosedObject[RestBlockHeaderInfo]
  GetBlockHeadersResponse* = DataEnclosedObject[seq[RestBlockHeaderInfo]]
  GetBlockRootResponse* = DataOptimisticObject[RestRoot]
  GetDebugChainHeadsResponse* = DataEnclosedObject[seq[RestChainHead]]
  GetDepositContractResponse* = DataEnclosedObject[RestDepositContract]
  GetDepositSnapshotResponse* = DataEnclosedObject[RestDepositSnapshot]
  GetEpochCommitteesResponse* = DataEnclosedObject[seq[RestBeaconStatesCommittees]]
  GetForkScheduleResponse* = DataEnclosedObject[seq[Fork]]
  GetGenesisResponse* = DataEnclosedObject[RestGenesis]
  GetHeaderResponseBellatrix* = DataVersionEnclosedObject[bellatrix_mev.SignedBuilderBid]
  GetHeaderResponseCapella* = DataVersionEnclosedObject[capella_mev.SignedBuilderBid]
  GetNetworkIdentityResponse* = DataEnclosedObject[RestNetworkIdentity]
  GetPeerCountResponse* = DataMetaEnclosedObject[RestPeerCount]
  GetPeerResponse* = DataMetaEnclosedObject[RestNodePeer]
  GetPeersResponse* = DataMetaEnclosedObject[seq[RestNodePeer]]
  GetPoolAttestationsResponse* = DataEnclosedObject[seq[Attestation]]
  GetPoolAttesterSlashingsResponse* = DataEnclosedObject[seq[AttesterSlashing]]
  GetPoolProposerSlashingsResponse* = DataEnclosedObject[seq[ProposerSlashing]]
  GetPoolVoluntaryExitsResponse* = DataEnclosedObject[seq[SignedVoluntaryExit]]
  GetProposerDutiesResponse* = DataRootEnclosedObject[seq[RestProposerDuty]]
  GetSpecResponse* = DataEnclosedObject[RestSpec]
  GetSpecVCResponse* = DataEnclosedObject[RestSpecVC]
  GetStateFinalityCheckpointsResponse* = DataEnclosedObject[RestBeaconStatesFinalityCheckpoints]
  GetStateForkResponse* = DataEnclosedObject[Fork]
  GetStateRootResponse* = DataOptimisticObject[RestRoot]
  GetStateValidatorBalancesResponse* = DataEnclosedObject[seq[RestValidatorBalance]]
  GetStateValidatorResponse* = DataEnclosedObject[RestValidator]
  GetStateValidatorsResponse* = DataOptimisticObject[seq[RestValidator]]
  GetSyncCommitteeDutiesResponse* = DataOptimisticObject[seq[RestSyncCommitteeDuty]]
  GetSyncingStatusResponse* = DataEnclosedObject[RestSyncInfo]
  GetVersionResponse* = DataEnclosedObject[RestNodeVersion]
  GetEpochSyncCommitteesResponse* = DataEnclosedObject[RestEpochSyncCommittee]
  ProduceAttestationDataResponse* = DataEnclosedObject[AttestationData]
  ProduceBlockResponseV2* = ForkedBeaconBlock
  ProduceBlindedBlockResponse* = ForkedBlindedBeaconBlock
  ProduceSyncCommitteeContributionResponse* = DataEnclosedObject[SyncCommitteeContribution]
  SubmitBlindedBlockResponseBellatrix* = DataEnclosedObject[bellatrix.ExecutionPayload]
  SubmitBlindedBlockResponseCapella* = DataEnclosedObject[capella.ExecutionPayload]
  GetValidatorsActivityResponse* = DataEnclosedObject[seq[RestActivityItem]]
  GetValidatorsLivenessResponse* = DataEnclosedObject[seq[RestLivenessItem]]

func `==`*(a, b: RestValidatorIndex): bool =
  uint64(a) == uint64(b)

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
    RestBlockInfo(slot: blck.message.slot, blck: blck.root)

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
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.AggregationSlot,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    aggregationSlot: Web3SignerAggregationSlotData(slot: data)
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: AggregateAndProof,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.AggregateAndProof,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    aggregateAndProof: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: AttestationData,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.Attestation,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    attestation: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: phase0.BeaconBlock,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.Block,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    blck: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: Web3SignerForkedBeaconBlock,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.BlockV2,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    beaconBlock: data
  )

func init*(t: typedesc[Web3SignerRequest], genesisForkVersion: Version,
           data: DepositMessage,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.Deposit,
    signingRoot: signingRoot,
    deposit: Web3SignerDepositData(
      pubkey: data.pubkey,
      withdrawalCredentials: data.withdrawalCredentials,
      genesisForkVersion: genesisForkVersion,
      amount: data.amount
    )
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: Epoch,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.RandaoReveal,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    randaoReveal: Web3SignerRandaoRevealData(epoch: data)
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, data: VoluntaryExit,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.VoluntaryExit,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    voluntaryExit: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest, blockRoot: Eth2Digest,
           slot: Slot, signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.SyncCommitteeMessage,
    forkInfo: some(Web3SignerForkInfo(
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
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.SyncCommitteeSelectionProof,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    syncAggregatorSelectionData: data
  )

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest,
           data: ContributionAndProof,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.SyncCommitteeContributionAndProof,
    forkInfo: some(Web3SignerForkInfo(
      fork: fork, genesis_validators_root: genesis_validators_root
    )),
    signingRoot: signingRoot,
    syncCommitteeContributionAndProof: data
  )

from stew/byteutils import to0xHex

func init*(t: typedesc[Web3SignerRequest], fork: Fork,
           genesis_validators_root: Eth2Digest,
           data: ValidatorRegistrationV1,
           signingRoot: Option[Eth2Digest] = none[Eth2Digest]()
          ): Web3SignerRequest =
  Web3SignerRequest(
    kind: Web3SignerRequestKind.ValidatorRegistration,
    forkInfo: some(Web3SignerForkInfo(
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
