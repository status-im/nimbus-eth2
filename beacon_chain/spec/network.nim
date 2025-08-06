# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  "."/[helpers, forks],
  "."/datatypes/base

export base

const
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/phase0/p2p-interface.md#topics-and-messages
  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/capella/p2p-interface.md#topics-and-messages
  topicBeaconBlocksSuffix = "beacon_block/ssz_snappy"
  topicVoluntaryExitsSuffix = "voluntary_exit/ssz_snappy"
  topicProposerSlashingsSuffix = "proposer_slashing/ssz_snappy"
  topicAttesterSlashingsSuffix = "attester_slashing/ssz_snappy"
  topicAggregateAndProofsSuffix = "beacon_aggregate_and_proof/ssz_snappy"
  topicBlsToExecutionChangeSuffix = "bls_to_execution_change/ssz_snappy"

const
  # The spec now includes this as a bare uint64 as `RESP_TIMEOUT`
  RESP_TIMEOUT_DUR* = RESP_TIMEOUT.int64.seconds

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/altair/light-client/p2p-interface.md#configuration
  MAX_REQUEST_LIGHT_CLIENT_UPDATES* = 128

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#configuration
  MAX_REQUEST_DATA_COLUMN_SIDECARS*: uint64 =
    MAX_REQUEST_BLOCKS_DENEB * NUMBER_OF_COLUMNS

  defaultEth2TcpPort* = 9000
  defaultEth2TcpPortDesc* = $defaultEth2TcpPort

  # This is not part of the spec! But it's port which Lighthouse uses
  defaultEth2RestPort* = 5052
  defaultEth2RestPortDesc* = $defaultEth2RestPort

  enrAttestationSubnetsField* = "attnets"
  enrSyncSubnetsField* = "syncnets"
  enrCustodySubnetCountField* = "cgc"
  enrNextForkDigestField* = "nfd"
  enrForkIdField* = "eth2"

template eth2Prefix(forkDigest: ForkDigest): string =
  "/eth2/" & $forkDigest & "/"

func getBeaconBlocksTopic*(forkDigest: ForkDigest): string =
  eth2Prefix(forkDigest) & topicBeaconBlocksSuffix

func getVoluntaryExitsTopic*(forkDigest: ForkDigest): string =
  eth2Prefix(forkDigest) & topicVoluntaryExitsSuffix

func getProposerSlashingsTopic*(forkDigest: ForkDigest): string =
  eth2Prefix(forkDigest) & topicProposerSlashingsSuffix

func getAttesterSlashingsTopic*(forkDigest: ForkDigest): string =
  eth2Prefix(forkDigest) & topicAttesterSlashingsSuffix

func getAggregateAndProofsTopic*(forkDigest: ForkDigest): string =
  eth2Prefix(forkDigest) & topicAggregateAndProofsSuffix

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.9/specs/capella/p2p-interface.md#topics-and-messages
func getBlsToExecutionChangeTopic*(forkDigest: ForkDigest): string =
  eth2Prefix(forkDigest) & topicBlsToExecutionChangeSuffix

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/validator.md#broadcast-attestation
func compute_subnet_for_attestation*(
    committees_per_slot: uint64, slot: Slot, committee_index: CommitteeIndex):
    SubnetId =
  ## Compute the correct subnet for an attestation for Phase 0.
  # Note, this mimics expected future behavior where attestations will be
  # mapped to their shard subnet.
  let
    slots_since_epoch_start = slot.since_epoch_start()
    committees_since_epoch_start =
      committees_per_slot * slots_since_epoch_start

  SubnetId(
    (committees_since_epoch_start + committee_index.asUInt64) mod
    ATTESTATION_SUBNET_COUNT)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/phase0/validator.md#broadcast-attestation
func getAttestationTopic*(forkDigest: ForkDigest,
                          subnetId: SubnetId): string =
  ## For subscribing and unsubscribing to/from a subnet.
  eth2Prefix(forkDigest) & "beacon_attestation_" & $(subnetId) & "/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/altair/p2p-interface.md#topics-and-messages
func getSyncCommitteeTopic*(forkDigest: ForkDigest,
                            subcommitteeIdx: SyncSubcommitteeIndex): string =
  ## For subscribing and unsubscribing to/from a subnet.
  eth2Prefix(forkDigest) & "sync_committee_" & $subcommitteeIdx & "/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/altair/p2p-interface.md#topics-and-messages
func getSyncCommitteeContributionAndProofTopic*(forkDigest: ForkDigest): string =
  ## For subscribing and unsubscribing to/from a subnet.
  eth2Prefix(forkDigest) & "sync_committee_contribution_and_proof/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.4/specs/deneb/p2p-interface.md#blob_sidecar_subnet_id
func getBlobSidecarTopic*(forkDigest: ForkDigest,
                          subnet_id: BlobId): string =
  eth2Prefix(forkDigest) & "blob_sidecar_" & $subnet_id & "/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.3/specs/deneb/validator.md#sidecar
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.2/specs/electra/validator.md#sidecar
func compute_subnet_for_blob_sidecar*(
    cfg: RuntimeConfig, slot: Slot, blob_index: BlobIndex): BlobId =
  let subnetCount =
    if slot >= cfg.ELECTRA_FORK_EPOCH.start_slot:
      cfg.BLOB_SIDECAR_SUBNET_COUNT_ELECTRA
    else:
      cfg.BLOB_SIDECAR_SUBNET_COUNT
  BlobId(blob_index mod subnetCount)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/fulu/p2p-interface.md#compute_subnet_for_data_column_sidecar
func compute_subnet_for_data_column_sidecar*(column_index: ColumnIndex): uint64 =
    uint64(column_index mod DATA_COLUMN_SIDECAR_SUBNET_COUNT)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.3/specs/altair/light-client/p2p-interface.md#light_client_finality_update
func getLightClientFinalityUpdateTopic*(forkDigest: ForkDigest): string =
  ## For broadcasting or obtaining the latest `LightClientFinalityUpdate`.
  eth2Prefix(forkDigest) & "light_client_finality_update/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#light_client_optimistic_update
func getLightClientOptimisticUpdateTopic*(forkDigest: ForkDigest): string =
  ## For broadcasting or obtaining the latest `LightClientOptimisticUpdate`.
  eth2Prefix(forkDigest) & "light_client_optimistic_update/ssz_snappy"

func getForkDigest(
    cfg: RuntimeConfig, genesis_validators_root: Eth2Digest,
    current_fork_version: Version, epoch: Epoch): ForkDigest =
  if epoch >= cfg.FULU_FORK_EPOCH:
    compute_fork_digest_fulu(cfg, genesis_validators_root, epoch)
  else:
    compute_fork_digest(current_fork_version, genesis_validators_root)

func getENRForkID*(cfg: RuntimeConfig,
                   epoch: Epoch,
                   genesis_validators_root: Eth2Digest): ENRForkID =
  let
    current_fork_version = cfg.forkVersionAtEpoch(epoch)
    next_fork_version = if cfg.nextForkEpochAtEpoch(epoch) == FAR_FUTURE_EPOCH:
      current_fork_version
    else:
      cfg.forkVersionAtEpoch(cfg.nextForkEpochAtEpoch(epoch))
    fork_digest = cfg.getForkDigest(
      genesis_validators_root, current_fork_version, epoch)
  ENRForkID(
    fork_digest: fork_digest,
    next_fork_version: next_fork_version,
    next_fork_epoch: cfg.nextForkEpochAtEpoch(epoch))

func getDiscoveryForkID*(cfg: RuntimeConfig,
                         epoch: Epoch,
                         genesis_validators_root: Eth2Digest): ENRForkID =
  # Until 1 epoch from fork, return pre-fork value.
  if cfg.nextForkEpochAtEpoch(epoch) - epoch <= 1:
    getENRForkID(cfg, epoch, genesis_validators_root)
  else:
    let
      current_fork_version = cfg.forkVersionAtEpoch(epoch)
      fork_digest = cfg.getForkDigest(
        genesis_validators_root, current_fork_version, epoch)
    ENRForkID(
      fork_digest: fork_digest,
      next_fork_version: current_fork_version,
      next_fork_epoch: FAR_FUTURE_EPOCH)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/altair/p2p-interface.md#transitioning-the-gossip
type GossipState* = HashSet[Epoch]
func getTargetGossipState*(epoch: Epoch, cfg: RuntimeConfig, isBehind: bool):
    GossipState =
  if isBehind:
    return HashSet[Epoch]()

  doAssert cfg.BELLATRIX_FORK_EPOCH >= cfg.ALTAIR_FORK_EPOCH
  doAssert cfg.CAPELLA_FORK_EPOCH >= cfg.BELLATRIX_FORK_EPOCH
  doAssert cfg.DENEB_FORK_EPOCH >= cfg.CAPELLA_FORK_EPOCH
  doAssert cfg.ELECTRA_FORK_EPOCH >= cfg.DENEB_FORK_EPOCH
  doAssert cfg.FULU_FORK_EPOCH >= cfg.ELECTRA_FORK_EPOCH

  # https://github.com/ethereum/consensus-specs/issues/2902
  # Don't care whether ALTAIR_FORK_EPOCH == BELLATRIX_FORK_EPOCH or
  # BELLATRIX_FORK_EPOCH == CAPELLA_FORK_EPOCH works, because those
  # theoretically possible networks are ill-defined regardless, and
  # consequently prohibited by checkForkConsistency(). Therefore, a
  # transitional epoch always exists, for every fork.
  var targetForkEpochs: GossipState

  template maybeIncludeFork(
      targetForkEpoch: Epoch, successiveForkEpoch: Epoch) =
    # Subscribe one epoch ahead
    if epoch + 1 >= targetForkEpoch and epoch < successiveForkEpoch:
      targetForkEpochs.incl targetForkEpoch

  maybeIncludeFork(GENESIS_EPOCH,            cfg.ALTAIR_FORK_EPOCH)
  maybeIncludeFork(cfg.ALTAIR_FORK_EPOCH,    cfg.BELLATRIX_FORK_EPOCH)
  maybeIncludeFork(cfg.BELLATRIX_FORK_EPOCH, cfg.CAPELLA_FORK_EPOCH)
  maybeIncludeFork(cfg.CAPELLA_FORK_EPOCH,   cfg.DENEB_FORK_EPOCH)
  maybeIncludeFork(cfg.DENEB_FORK_EPOCH,     cfg.ELECTRA_FORK_EPOCH)
  maybeIncludeFork(cfg.ELECTRA_FORK_EPOCH,   cfg.FULU_FORK_EPOCH)
  maybeIncludeFork(cfg.FULU_FORK_EPOCH,      FAR_FUTURE_EPOCH)
  var successorForkEpoch = FAR_FUTURE_EPOCH
  for bpo in cfg.BLOB_SCHEDULE:
    # Always in reverse, sorted order from high to low epochs
    # TODO _should_ be ok to maybeInclude in this reverse order due to the
    # epoch < successiveForkEpoch guard.
    maybeIncludeFork(bpo.EPOCH, successorForkEpoch)
    successorForkEpoch = bpo.EPOCH

  doAssert len(targetForkEpochs) <= 2
  targetForkEpochs

func nearSyncCommitteePeriod*(epoch: Epoch): Opt[uint64] =
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/altair/validator.md#sync-committee-subnet-stability
  if epoch.is_sync_committee_period():
    return Opt.some 0'u64
  let epochsBefore =
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD - epoch.since_sync_committee_period_start()
  if epoch.is_sync_committee_period() or epochsBefore <= SYNC_COMMITTEE_SUBNET_COUNT:
    return Opt.some epochsBefore

  Opt.none(uint64)

func getSyncSubnets*(
    nodeHasPubkey: proc(pubkey: ValidatorPubKey):
      bool {.noSideEffect, raises: [].},
    syncCommittee: SyncCommittee): SyncnetBits =
  var res: SyncnetBits
  for i, pubkey in syncCommittee.pubkeys:
    if not nodeHasPubkey(pubkey):
      continue

    # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.0/specs/altair/validator.md#broadcast-sync-committee-message
    # The first quarter of the pubkeys map to subnet 0, the second quarter to
    # subnet 1, the third quarter to subnet 2 and the final quarter to subnet
    # 3.
    res.setBit(i div (SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT))
  res

iterator blobSidecarTopics*(
    forkDigest: ForkDigest, subnetCount: uint64): string =
  for subnet_id in 0.BlobId ..< subnetCount.BlobId:
    yield getBlobSidecarTopic(forkDigest, subnet_id)

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.10/specs/fulu/p2p-interface.md#data_column_sidecar_subnet_id
func getDataColumnSidecarTopic*(forkDigest: ForkDigest,
                                subnet_id: uint64): string =
  eth2Prefix(forkDigest) & "data_column_sidecar_" & $subnet_id & "/ssz_snappy"

iterator dataColumnSidecarTopics*(forkDigest: ForkDigest,
                                  targetSubnetCount: uint64): string =
  for subnet_id in 0'u64..<targetSubnetCount:
    yield getDataColumnSidecarTopic(forkDigest, subnet_id)
