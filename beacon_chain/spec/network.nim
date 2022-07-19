# beacon_chain
# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

# References to `vFuture` refer to the pre-release proposal of the libp2p based
# light client sync protocol. Conflicting release versions are not in use.
# https://github.com/ethereum/consensus-specs/pull/2802

import
  "."/[helpers, forks],
  "."/datatypes/base

export base

const
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/p2p-interface.md#topics-and-messages
  topicBeaconBlocksSuffix* = "beacon_block/ssz_snappy"
  topicVoluntaryExitsSuffix* = "voluntary_exit/ssz_snappy"
  topicProposerSlashingsSuffix* = "proposer_slashing/ssz_snappy"
  topicAttesterSlashingsSuffix* = "attester_slashing/ssz_snappy"
  topicAggregateAndProofsSuffix* = "beacon_aggregate_and_proof/ssz_snappy"

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/p2p-interface.md#configuration
  MAX_CHUNK_SIZE* = 1 * 1024 * 1024 # bytes
  GOSSIP_MAX_SIZE* = 1 * 1024 * 1024 # bytes
  TTFB_TIMEOUT* = 5.seconds
  RESP_TIMEOUT* = 10.seconds

  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/bellatrix/p2p-interface.md#configuration
  GOSSIP_MAX_SIZE_BELLATRIX* = 10 * 1024 * 1024 # bytes
  MAX_CHUNK_SIZE_BELLATRIX* = 10 * 1024 * 1024 # bytes

  defaultEth2TcpPort* = 9000

  # This is not part of the spec! But its port which uses Lighthouse
  DefaultEth2RestPort* = 5052
  DefaultEth2RestPortDesc* = $DefaultEth2RestPort

  enrAttestationSubnetsField* = "attnets"
  enrSyncSubnetsField* = "syncnets"
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

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#broadcast-attestation
func compute_subnet_for_attestation*(
    committees_per_slot: uint64, slot: Slot, committee_index: CommitteeIndex):
    SubnetId =
  # Compute the correct subnet for an attestation for Phase 0.
  # Note, this mimics expected Phase 1 behavior where attestations will be
  # mapped to their shard subnet.
  let
    slots_since_epoch_start = slot.since_epoch_start()
    committees_since_epoch_start =
      committees_per_slot * slots_since_epoch_start

  SubnetId(
    (committees_since_epoch_start + committee_index.asUInt64) mod
    ATTESTATION_SUBNET_COUNT)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/phase0/validator.md#broadcast-attestation
func getAttestationTopic*(forkDigest: ForkDigest,
                          subnetId: SubnetId): string =
  ## For subscribing and unsubscribing to/from a subnet.
  eth2Prefix(forkDigest) & "beacon_attestation_" & $(subnetId) & "/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/p2p-interface.md#topics-and-messages
func getSyncCommitteeTopic*(forkDigest: ForkDigest,
                            subcommitteeIdx: SyncSubcommitteeIndex): string =
  ## For subscribing and unsubscribing to/from a subnet.
  eth2Prefix(forkDigest) & "sync_committee_" & $subcommitteeIdx & "/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/p2p-interface.md#topics-and-messages
func getSyncCommitteeContributionAndProofTopic*(forkDigest: ForkDigest): string =
  ## For subscribing and unsubscribing to/from a subnet.
  eth2Prefix(forkDigest) & "sync_committee_contribution_and_proof/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#light_client_finality_update
func getLightClientFinalityUpdateTopic*(forkDigest: ForkDigest): string =
  ## For broadcasting or obtaining the latest `LightClientFinalityUpdate`.
  eth2Prefix(forkDigest) & "light_client_finality_update_v0/ssz_snappy"

# https://github.com/ethereum/consensus-specs/blob/vFuture/specs/altair/sync-protocol.md#light_client_optimistic_update
func getLightClientOptimisticUpdateTopic*(forkDigest: ForkDigest): string =
  ## For broadcasting or obtaining the latest `LightClientOptimisticUpdate`.
  eth2Prefix(forkDigest) & "light_client_optimistic_update_v0/ssz_snappy"

func getENRForkID*(cfg: RuntimeConfig,
                   epoch: Epoch,
                   genesis_validators_root: Eth2Digest): ENRForkID =
  let
    current_fork_version = cfg.forkVersionAtEpoch(epoch)
    next_fork_version = if cfg.nextForkEpochAtEpoch(epoch) == FAR_FUTURE_EPOCH:
      current_fork_version
    else:
      cfg.forkVersionAtEpoch(cfg.nextForkEpochAtEpoch(epoch))
    fork_digest = compute_fork_digest(current_fork_version,
                                      genesis_validators_root)
  ENRForkID(
    fork_digest: fork_digest,
    next_fork_version: next_fork_version,
    next_fork_epoch: cfg.nextForkEpochAtEpoch(epoch))

func getDiscoveryForkID*(cfg: RuntimeConfig,
                   epoch: Epoch,
                   genesis_validators_root: Eth2Digest): ENRForkID =
  # Until 1 epoch from fork, returns pre-fork value
  if epoch + 1 >= cfg.ALTAIR_FORK_EPOCH:
    getENRForkID(cfg, epoch, genesis_validators_root)
  else:
    let
      current_fork_version = cfg.forkVersionAtEpoch(epoch)
      fork_digest = compute_fork_digest(current_fork_version,
                                        genesis_validators_root)
    ENRForkID(
      fork_digest: fork_digest,
      next_fork_version: current_fork_version,
      next_fork_epoch: FAR_FUTURE_EPOCH)

# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/p2p-interface.md#transitioning-the-gossip
type GossipState* = set[BeaconStateFork]
func getTargetGossipState*(
    epoch, ALTAIR_FORK_EPOCH, BELLATRIX_FORK_EPOCH: Epoch, isBehind: bool):
    GossipState =
  if isBehind:
    {}

  # The order of these checks doesn't matter.
  elif epoch >= BELLATRIX_FORK_EPOCH:
    {BeaconStateFork.Bellatrix}
  elif epoch + 1 < ALTAIR_FORK_EPOCH:
    {BeaconStateFork.Phase0}

  # Order remaining checks so ALTAIR_FORK_EPOCH == BELLATRIX_FORK_EPOCH works
  # and when the transition zones align contiguously, or are separated by
  # intermediate pure-Altair epochs.
  #
  # In the first case, should never enable Altair, and there's also never
  # a Phase -> Altair, or Altair -> Bellatrix gossip transition epoch. In
  # contiguous Phase0 -> Altair and Altair -> Bellatrix transitions, that
  # pure Altair state gossip state never occurs, but it works without any
  # special cases so long as one checks for transition-to-fork+1 before a
  # pure fork gossip state.
  #
  # Therefore, check for transition-to-merge before pure-Altair.
  elif epoch + 1 >= BELLATRIX_FORK_EPOCH:
    # As there are only two fork epochs and there's no transition to phase0
    {if ALTAIR_FORK_EPOCH == BELLATRIX_FORK_EPOCH:
       BeaconStateFork.Phase0
     else:
       BeaconStateFork.Altair,
     BeaconStateFork.Bellatrix}
  elif epoch >= ALTAIR_FORK_EPOCH:
    {BeaconStateFork.Altair}

  # Must be after the case which catches phase0 => merge
  elif epoch + 1 >= ALTAIR_FORK_EPOCH:
    {BeaconStateFork.Phase0, BeaconStateFork.Altair}
  else:
    raiseAssert "Unknown target gossip state"

func nearSyncCommitteePeriod*(epoch: Epoch): Option[uint64] =
  # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#sync-committee-subnet-stability
  if epoch.is_sync_committee_period():
    return some 0'u64
  let epochsBefore =
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD - epoch.since_sync_committee_period_start()
  if epoch.is_sync_committee_period() or epochsBefore <= SYNC_COMMITTEE_SUBNET_COUNT:
    return some epochsBefore

  none(uint64)

func getSyncSubnets*(
    nodeHasPubkey: proc(pubkey: ValidatorPubKey):
      bool {.noSideEffect, raises: [Defect].},
    syncCommittee: SyncCommittee): SyncnetBits =
  var res: SyncnetBits
  for i, pubkey in syncCommittee.pubkeys:
    if not nodeHasPubkey(pubkey):
      continue

    # https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/specs/altair/validator.md#broadcast-sync-committee-message
    # The first quarter of the pubkeys map to subnet 0, the second quarter to
    # subnet 1, the third quarter to subnet 2 and the final quarter to subnet
    # 3.
    res.setBit(i div (SYNC_COMMITTEE_SIZE div SYNC_COMMITTEE_SUBNET_COUNT))
  res
