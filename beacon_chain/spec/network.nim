# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import strformat

const
  topicBeaconBlocks* = "/eth2/beacon_block/ssz"
  topicAttestationSuffix* = "_beacon_attestation/ssz"
  topicVoluntaryExits* = "/eth2/voluntary_exit/ssz"
  topicProposerSlashings* = "/eth2/proposer_slashing/ssz"
  topicAttesterSlashings* = "/eth2/attester_slashing/ssz"

  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/p2p-interface.md#configuration
  ATTESTATION_SUBNET_COUNT* = 64

func getAttestationTopic*(committeeIndex: uint64): string =
  # https://github.com/ethereum/eth2.0-specs/blob/v0.11.0/specs/phase0/validator.md#broadcast-attestation
  let topicIndex = committeeIndex mod ATTESTATION_SUBNET_COUNT
  &"/eth2/committee_index{topicIndex}{topicAttestationSuffix}"
