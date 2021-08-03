# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  presto/client,
  ../datatypes/[phase0, altair],
  "."/[rest_types, eth2_rest_serialization]

export client, rest_types, eth2_rest_serialization

proc getGenesis*(): RestResponse[GetGenesisResponse] {.
     rest, endpoint: "/eth/v1/beacon/genesis",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getGenesis

proc getStateRoot*(state_id: StateIdent): RestResponse[GetStateRootResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/root",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateRoot

proc getStateFork*(state_id: StateIdent): RestResponse[GetStateForkResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/fork",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateFork

proc getStateFinalityCheckpoints*(state_id: StateIdent
          ): RestResponse[GetStateFinalityCheckpointsResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/states/{state_id}/finality_checkpoints",
     meth: MethodGet.}

proc getStateValidators*(state_id: StateIdent,
                         id: seq[ValidatorIdent]
                        ): RestResponse[GetStateValidatorsResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/validators",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidators

proc getStateValidator*(state_id: StateIdent,
                        validator_id: ValidatorIdent
                       ): RestResponse[GetStateValidatorResponse] {.
     rest,
     endpoint: "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidator

proc getStateValidatorBalances*(state_id: StateIdent
                        ): RestResponse[GetStateValidatorBalancesResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/validator_balances",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getStateValidators

proc getEpochCommittees*(state_id: StateIdent
                        ): RestResponse[GetEpochCommitteesResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/committees",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getEpochCommittees

# TODO altair
# proc getEpochSyncCommittees*(state_id: StateIdent
#                         ): RestResponse[GetEpochSyncCommitteesResponse] {.
#      rest, endpoint: "/eth/v1/beacon/states/{state_id}/sync_committees",
#      meth: MethodGet.}
#   ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getEpochSyncCommittees

proc getBlockHeaders*(slot: Option[Slot], parent_root: Option[Eth2Digest]
                        ): RestResponse[GetBlockHeadersResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/headers",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeaders

proc getBlockHeader*(block_id: BlockIdent): RestResponse[GetBlockHeaderResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/headers/{block_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockHeader

proc publishBlock*(body: phase0.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/publishBlock

proc getBlock*(block_id: BlockIdent): RestResponse[GetBlockResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/blocks/{block_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlock

# TODO altair
# proc getBlockV2*(block_id: BlockIdent): RestResponse[GetBlockV2Response] {.
#      rest, endpoint: "/api/eth/v2/beacon/blocks/{block_id}",
#      meth: MethodGet.}
#   ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockV2

proc getBlockRoot*(block_id: BlockIdent): RestResponse[GetBlockRootResponse] {.
     rest, endpoint: "/eth/v1/beacon/blocks/{block_id}/root",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockRoot

proc getBlockAttestations*(block_id: BlockIdent
                        ): RestResponse[GetBlockAttestationsResponse] {.
     rest, endpoint: "/eth/v1/beacon/blocks/{block_id}/attestations",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getBlockAttestations

proc getPoolAttestations*(
    slot: Option[Slot],
    committee_index: Option[CommitteeIndex]
              ): RestResponse[GetPoolAttestationsResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/pool/attestations",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolAttestations

proc submitPoolAttestations*(body: seq[Attestation]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/pool/attestations",
     meth: MethodPost.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttestations

proc getPoolAttesterSlashings*(): RestResponse[GetPoolAttesterSlashingsResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/pool/attester_slashings",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolAttesterSlashings

proc submitPoolAttesterSlashings*(body: AttesterSlashing): RestPlainResponse {.
     rest, endpoint: "/api/eth/v1/beacon/pool/attester_slashings",
     meth: MethodPost.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolAttesterSlashings

proc getPoolProposerSlashings*(): RestResponse[GetPoolProposerSlashingsResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/pool/proposer_slashings",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolProposerSlashings

proc submitPoolProposerSlashings*(body: ProposerSlashing): RestPlainResponse {.
     rest, endpoint: "/api/eth/v1/beacon/pool/proposer_slashings",
     meth: MethodPost.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolProposerSlashings

# TODO Altair
# proc submitPoolSyncCommitteeSignatures*(body: seq[RestSyncCommitteeSignature]): RestPlainResponse {.
#      rest, endpoint: "/eth/v1/beacon/pool/sync_committees",
#      meth: MethodPost.}
#   ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolSyncCommitteeSignatures

proc getPoolVoluntaryExits*(): RestResponse[GetPoolVoluntaryExitsResponse] {.
     rest, endpoint: "/api/eth/v1/beacon/pool/voluntary_exits",
     meth: MethodGet.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/getPoolVoluntaryExits

proc submitPoolVoluntaryExit*(body: SignedVoluntaryExit): RestPlainResponse {.
     rest, endpoint: "/api/eth/v1/beacon/pool/voluntary_exits",
     meth: MethodPost.}
  ## https://ethereum.github.io/eth2.0-APIs/#/Beacon/submitPoolVoluntaryExit
