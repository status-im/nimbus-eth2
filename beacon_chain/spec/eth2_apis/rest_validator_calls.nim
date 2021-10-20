# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, presto/client,
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getAttesterDuties*(epoch: Epoch,
                        body: seq[ValidatorIndex]
                       ): RestResponse[GetAttesterDutiesResponse] {.
     rest, endpoint: "/eth/v1/validator/duties/attester/{epoch}",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties

proc getProposerDuties*(epoch: Epoch): RestResponse[GetProposerDutiesResponse] {.
     rest, endpoint: "/eth/v1/validator/duties/proposer/{epoch}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties

proc getSyncCommitteeDuties*(epoch: Epoch,
                             body: seq[ValidatorIndex]
                            ): RestResponse[GetSyncCommitteeDutiesResponse] {.
     rest, endpoint: "/eth/v1/validator/duties/sync/{epoch}",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getSyncCommitteeDuties

proc produceBlock*(slot: Slot, randao_reveal: ValidatorSig,
                   graffiti: GraffitiBytes
                  ): RestResponse[ProduceBlockResponse] {.
     rest, endpoint: "/eth/v1/validator/blocks/{slot}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceBlock

proc produceBlockV2*(slot: Slot, randao_reveal: ValidatorSig,
                     graffiti: GraffitiBytes
                    ): RestResponse[ProduceBlockResponseV2] {.
       rest, endpoint: "/eth/v2/validator/blocks/{slot}",
       meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV2

proc produceAttestationData*(slot: Slot,
                             committee_index: CommitteeIndex
                            ): RestResponse[ProduceAttestationDataResponse] {.
     rest, endpoint: "/eth/v1/validator/attestation_data",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData

proc getAggregatedAttestation*(attestation_data_root: Eth2Digest,
                               slot: Slot): RestResponse[GetAggregatedAttestationResponse] {.
     rest, endpoint: "/eth/v1/validator/aggregate_attestation"
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestation

proc publishAggregateAndProofs*(body: seq[SignedAggregateAndProof]
                               ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/aggregate_and_proofs",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/publishAggregateAndProofs

proc prepareBeaconCommitteeSubnet*(body: seq[RestCommitteeSubscription]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/beacon_committee_subscriptions",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet

proc prepareSyncCommitteeSubnets*(body: seq[RestSyncCommitteeSubscription]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/sync_committee_subscriptions",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/prepareSyncCommitteeSubnets

proc produceSyncCommitteeContribution*(slot: Slot,
                                       subcommittee_index: SyncSubcommitteeIndex,
                                       beacon_block_root: Eth2Digest): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/sync_committee_contribution",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution

proc publishContributionAndProofs*(body: seq[RestSignedContributionAndProof]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/contribution_and_proofs",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/publishContributionAndProofs
