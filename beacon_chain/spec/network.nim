# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  strformat,
  stew/byteutils,
  datatypes

const
  topicBeaconBlocksSuffix* = "beacon_block/ssz"
  topicAttestationsSuffix* = "_beacon_attestation/ssz"
  topicVoluntaryExitsSuffix* = "voluntary_exit/ssz"
  topicProposerSlashingsSuffix* = "proposer_slashing/ssz"
  topicAttesterSlashingsSuffix* = "attester_slashing/ssz"
  topicAggregateAndProofsSuffix* = "beacon_aggregate_and_proof/ssz"

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/p2p-interface.md#configuration
  ATTESTATION_SUBNET_COUNT* = 64

  defaultEth2TcpPort* = 9000

  # This is not part of the spec yet!
  defaultEth2RpcPort* = 9090

func getBeaconBlocksTopic*(forkDigest: ForkDigest): string =
  &"/eth2/{toHex forkDigest}/{topicBeaconBlocksSuffix}"

func getVoluntaryExitsTopic*(forkDigest: ForkDigest): string =
  &"/eth2/{toHex forkDigest}/{topicVoluntaryExitsSuffix}"

func getProposerSlashingsTopic*(forkDigest: ForkDigest): string =
  &"/eth2/{toHex forkDigest}/{topicProposerSlashingsSuffix}"

func getAttesterSlashingsTopic*(forkDigest: ForkDigest): string =
  &"/eth2/{toHex forkDigest}/{topicAttesterSlashingsSuffix}"

func getAggregateAndProofsTopic*(forkDigest: ForkDigest): string =
  &"/eth2/{toHex forkDigest}/{topicAggregateAndProofsSuffix}"

func getAttestationTopic*(forkDigest: ForkDigest, committeeIndex: uint64): string =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/validator.md#broadcast-attestation
  let topicIndex = committeeIndex mod ATTESTATION_SUBNET_COUNT
  &"/eth2/{toHex forkDigest}/committee_index{topicIndex}{topicAttestationsSuffix}"

