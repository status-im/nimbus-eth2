# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

const
  topicBeaconBlocks* = "/eth2/beacon_block/ssz"
  topicAttestations* = "/eth2/beacon_attestation/ssz"
  topicVoluntaryExits* = "/eth2/voluntary_exit/ssz"
  topicProposerSlashings* = "/eth2/proposer_slashing/ssz"
  topicAttesterSlashings* = "/eth2/attester_slashing/ssz"
