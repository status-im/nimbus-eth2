# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  strformat,
  datatypes

const
  topicBeaconBlocksSuffix* = "beacon_block/ssz"
  topicMainnetAttestationsSuffix* = "_beacon_attestation/ssz"
  topicVoluntaryExitsSuffix* = "voluntary_exit/ssz"
  topicProposerSlashingsSuffix* = "proposer_slashing/ssz"
  topicAttesterSlashingsSuffix* = "attester_slashing/ssz"
  topicInteropAttestationSuffix* = "beacon_attestation/ssz"
  topicAggregateAndProofsSuffix* = "beacon_aggregate_and_proof/ssz"

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#configuration
  ATTESTATION_SUBNET_COUNT* = 64

  defaultEth2TcpPort* = 9000

  # This is not part of the spec yet!
  defaultEth2RpcPort* = 9090

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#topics-and-messages
func getBeaconBlocksTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicBeaconBlocksSuffix}"
  except ValueError as e:
    raiseAssert e.msg

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#topics-and-messages
func getVoluntaryExitsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicVoluntaryExitsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#topics-and-messages
func getProposerSlashingsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicProposerSlashingsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#topics-and-messages
func getAttesterSlashingsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicAttesterSlashingsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#interop-3
func getInteropAttestationTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicInteropAttestationSuffix}"
  except ValueError as e:
    raiseAssert e.msg

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#topics-and-messages
func getAggregateAndProofsTopic*(forkDigest: ForkDigest): string =
  try:
    &"/eth2/{$forkDigest}/{topicAggregateAndProofsSuffix}"
  except ValueError as e:
    raiseAssert e.msg

# https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/p2p-interface.md#mainnet-3
func getMainnetAttestationTopic*(forkDigest: ForkDigest, committeeIndex: uint64): string =
  try:
    let topicIndex = committeeIndex mod ATTESTATION_SUBNET_COUNT
    &"/eth2/{$forkDigest}/committee_index{topicIndex}{topicMainnetAttestationsSuffix}"
  except ValueError as e:
    raiseAssert e.msg
