# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos, presto/client,
  "."/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getAttesterDuties*(
       epoch: Epoch,
       body: seq[ValidatorIndex]
     ): RestResponse[GetAttesterDutiesResponse] {.
     rest, endpoint: "/eth/v1/validator/duties/attester/{epoch}",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties

proc getAttesterDutiesPlain*(
       epoch: Epoch,
       body: seq[ValidatorIndex]
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/duties/attester/{epoch}",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getAttesterDuties

proc getProposerDuties*(
       epoch: Epoch
     ): RestResponse[GetProposerDutiesResponse] {.
     rest, endpoint: "/eth/v1/validator/duties/proposer/{epoch}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties

proc getProposerDutiesPlain*(
       epoch: Epoch
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/duties/proposer/{epoch}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getProposerDuties

proc getSyncCommitteeDuties*(
       epoch: Epoch,
       body: seq[ValidatorIndex]
     ): RestResponse[GetSyncCommitteeDutiesResponse] {.
     rest, endpoint: "/eth/v1/validator/duties/sync/{epoch}",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getSyncCommitteeDuties

proc getSyncCommitteeDutiesPlain*(
       epoch: Epoch,
       body: seq[ValidatorIndex]
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/duties/sync/{epoch}",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getSyncCommitteeDuties

proc produceBlockV2Plain*(
       slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v2/validator/blocks/{slot}",
     accept: preferSSZ, meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceBlockV2

proc produceBlindedBlockPlain*(
       slot: Slot,
       randao_reveal: ValidatorSig,
       graffiti: GraffitiBytes
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/blinded_blocks/{slot}",
     accept: preferSSZ, meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceBlindedBlock

proc produceAttestationData*(
       slot: Slot,
       committee_index: CommitteeIndex
     ): RestResponse[ProduceAttestationDataResponse] {.
     rest, endpoint: "/eth/v1/validator/attestation_data",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData

proc produceAttestationDataPlain*(
       slot: Slot,
       committee_index: CommitteeIndex
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/attestation_data",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceAttestationData

proc getAggregatedAttestation*(
       attestation_data_root: Eth2Digest,
       slot: Slot
     ): RestResponse[GetAggregatedAttestationResponse] {.
     rest, endpoint: "/eth/v1/validator/aggregate_attestation"
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestation

proc getAggregatedAttestationPlain*(
       attestation_data_root: Eth2Digest,
       slot: Slot
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/aggregate_attestation"
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/getAggregatedAttestation

proc publishAggregateAndProofs*(
       body: seq[SignedAggregateAndProof]
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/aggregate_and_proofs",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/publishAggregateAndProofs

proc prepareBeaconCommitteeSubnet*(
       body: seq[RestCommitteeSubscription]
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/beacon_committee_subscriptions",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/prepareBeaconCommitteeSubnet

proc prepareSyncCommitteeSubnets*(
       body: seq[RestSyncCommitteeSubscription]
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/sync_committee_subscriptions",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/prepareSyncCommitteeSubnets

proc produceSyncCommitteeContribution*(
       slot: Slot,
       subcommittee_index: SyncSubcommitteeIndex,
       beacon_block_root: Eth2Digest
     ): RestResponse[ProduceSyncCommitteeContributionResponse] {.
     rest, endpoint: "/eth/v1/validator/sync_committee_contribution",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution

proc produceSyncCommitteeContributionPlain*(
       slot: Slot,
       subcommittee_index: SyncSubcommitteeIndex,
       beacon_block_root: Eth2Digest
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/sync_committee_contribution",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/produceSyncCommitteeContribution

proc publishContributionAndProofs*(body: seq[RestSignedContributionAndProof]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/contribution_and_proofs",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/publishContributionAndProofs

proc prepareBeaconProposer*(body: seq[PrepareBeaconProposer]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/prepare_beacon_proposer",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/prepareBeaconProposer

proc registerValidator*(body: seq[SignedValidatorRegistrationV1]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/register_validator",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/registerValidator

proc getValidatorsLiveness*(epoch: Epoch,
                            body: seq[ValidatorIndex]
                           ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/liveness/{epoch}",
     meth: MethodPost.}

proc submitBeaconCommitteeSelectionsPlain*(
       body: seq[RestBeaconCommitteeSelection]
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/beacon_committee_selections",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/submitBeaconCommitteeSelections

proc submitSyncCommitteeSelectionsPlain*(
       body: seq[RestSyncCommitteeSelection]
     ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/validator/sync_committee_selections",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Validator/submitSyncCommitteeSelections

