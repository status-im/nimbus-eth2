# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[strformat, sets, random],
  ./datatypes, ./helpers, ./validator

const
  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/p2p-interface.md#topics-and-messages
  topicBeaconBlocksSuffix* = "beacon_block/ssz"
  topicVoluntaryExitsSuffix* = "voluntary_exit/ssz"
  topicProposerSlashingsSuffix* = "proposer_slashing/ssz"
  topicAttesterSlashingsSuffix* = "attester_slashing/ssz"
  topicAggregateAndProofsSuffix* = "beacon_aggregate_and_proof/ssz"

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#misc
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

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#broadcast-attestation
func compute_subnet_for_attestation*(
    committees_per_slot: uint64, slot: Slot, committee_index: CommitteeIndex):
    uint64 =
  # Compute the correct subnet for an attestation for Phase 0.
  # Note, this mimics expected Phase 1 behavior where attestations will be
  # mapped to their shard subnet.
  let
    slots_since_epoch_start = slot mod SLOTS_PER_EPOCH
    committees_since_epoch_start =
      committees_per_slot * slots_since_epoch_start

  (committees_since_epoch_start + committee_index.uint64) mod
    ATTESTATION_SUBNET_COUNT

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#broadcast-attestation
func getAttestationTopic*(forkDigest: ForkDigest, subnetIndex: uint64):
    string =
  # This is for subscribing or broadcasting manually to a known index.
  doAssert subnetIndex < ATTESTATION_SUBNET_COUNT

  try:
    &"/eth2/{$forkDigest}/beacon_attestation_{subnetIndex}/ssz"
  except ValueError as e:
    raiseAssert e.msg

func getAttestationTopic*(forkDigest: ForkDigest,
                          attestation: Attestation,
                          num_active_validators: uint64): string =
  getAttestationTopic(
    forkDigest,
    compute_subnet_for_attestation(
      get_committee_count_per_slot(num_active_validators),
      attestation.data.slot, attestation.data.index.CommitteeIndex))

func get_committee_assignments(
    state: BeaconState, epoch: Epoch,
    validator_indices: HashSet[ValidatorIndex]):
    seq[tuple[subnetIndex: uint64, slot: Slot]] =
  var cache = StateCache()

  let
    committees_per_slot = get_committee_count_per_slot(state, epoch, cache)
    start_slot = compute_start_slot_at_epoch(epoch)

  for slot in start_slot ..< start_slot + SLOTS_PER_EPOCH:
    for index in 0'u64 ..< committees_per_slot:
      let idx = index.CommitteeIndex
      if not disjoint(validator_indices,
          get_beacon_committee(state, slot, idx, cache).toHashSet):
        result.add(
          (compute_subnet_for_attestation(committees_per_slot, slot, idx),
            slot))

# https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#phase-0-attestation-subnet-stability
proc getStabilitySubnetLength*(): uint64 =
  EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION +
    rand(EPOCHS_PER_RANDOM_SUBNET_SUBSCRIPTION.int).uint64

proc get_attestation_subnet_changes*(
    state: BeaconState, attachedValidators: openarray[ValidatorIndex],
    prevAttestationSubnets: AttestationSubnets, epoch: Epoch):
    tuple[a: AttestationSubnets, b: set[uint8], c: set[uint8]] =
  static:
    doAssert ATTESTATION_SUBNET_COUNT == 64

  var attestationSubnets = prevAttestationSubnets

  # https://github.com/ethereum/eth2.0-specs/blob/v0.12.2/specs/phase0/validator.md#phase-0-attestation-subnet-stability
  let prevStabilitySubnet = {attestationSubnets.stabilitySubnet.uint8}
  if epoch >= attestationSubnets.stabilitySubnetExpirationEpoch:
    attestationSubnets.stabilitySubnet =
      rand(ATTESTATION_SUBNET_COUNT - 1).uint64
    attestationSubnets.stabilitySubnetExpirationEpoch =
      epoch + getStabilitySubnetLength()

  var nextEpochSubnets: set[uint8]
  for it in get_committee_assignments(
      state, state.slot.epoch + 1, attachedValidators.toHashSet):
    nextEpochSubnets.incl it.subnetIndex.uint8

  let
    epochParity = epoch mod 2
    stabilitySet = {attestationSubnets.stabilitySubnet.uint8}
    currentEpochSubnets = attestationSubnets.subscribedSubnets[1 - epochParity]

    expiringSubnets =
      (prevStabilitySubnet +
        attestationSubnets.subscribedSubnets[epochParity]) -
        nextEpochSubnets - currentEpochSubnets - stabilitySet
    newSubnets =
      (nextEpochSubnets + stabilitySet) -
        (currentEpochSubnets + prevStabilitySubnet)

  attestationSubnets.subscribedSubnets[epochParity] = newSubnets
  (attestationSubnets, expiringSubnets, newSubnets)
