# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  strformat,
  datatypes, helpers

const
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/p2p-interface.md#topics-and-messages
  topicBeaconBlocksSuffix* = "beacon_block/ssz"
  topicVoluntaryExitsSuffix* = "voluntary_exit/ssz"
  topicProposerSlashingsSuffix* = "proposer_slashing/ssz"
  topicAttesterSlashingsSuffix* = "attester_slashing/ssz"
  topicAggregateAndProofsSuffix* = "beacon_aggregate_and_proof/ssz"

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#misc
  ATTESTATION_SUBNET_COUNT* = 64

  defaultEth2TcpPort* = 9000

  # This is not part of the spec yet!
  defaultEth2RpcPort* = 9090

func getBeaconBlocksTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicBeaconBlocksSuffix}"
  except ValueError as e:
    raiseAssert e.msg

func getVoluntaryExitsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicVoluntaryExitsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

func getProposerSlashingsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicProposerSlashingsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

func getAttesterSlashingsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicAttesterSlashingsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

func getAggregateAndProofsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicAggregateAndProofsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#broadcast-attestation
func compute_subnet_for_attestation*(
    num_active_validators: uint64, attestation: Attestation): uint64 =
  # Compute the correct subnet for an attestation for Phase 0.
  # Note, this mimics expected Phase 1 behavior where attestations will be
  # mapped to their shard subnet.
  #
  # The spec version has params (state: BeaconState, attestation: Attestation),
  # but it's only to call get_committee_count_at_slot(), which needs only epoch
  # and the number of active validators.
  let
    slots_since_epoch_start = attestation.data.slot mod SLOTS_PER_EPOCH
    committees_since_epoch_start =
      get_committee_count_at_slot(num_active_validators) * slots_since_epoch_start

  (committees_since_epoch_start + attestation.data.index) mod ATTESTATION_SUBNET_COUNT

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.1/specs/phase0/validator.md#broadcast-attestation
func getAttestationTopic*(forkDigest: ForkDigest, subnetIndex: uint64):
    string =
  # This is for subscribing or broadcasting manually to a known index.
  try:
    &"/eth2/{$forkDigest}/beacon_attestation_{subnetIndex}/ssz"
  except ValueError as e:
    raiseAssert e.msg

func getAttestationTopic*(forkDigest: ForkDigest, attestation: Attestation, num_active_validators: uint64): string =
  getAttestationTopic(
    forkDigest,
    compute_subnet_for_attestation(num_active_validators, attestation))
