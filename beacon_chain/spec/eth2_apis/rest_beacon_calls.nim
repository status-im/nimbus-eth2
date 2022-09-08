# Copyright (c) 2018-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import
  chronos, presto/client, chronicles,
  ".."/".."/validators/slashing_protection_common,
  ".."/datatypes/[phase0, altair, bellatrix],
  ".."/[helpers, forks, keystore, eth2_ssz_serialization],
  "."/[rest_types, rest_common, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getGenesis*(): RestResponse[GetGenesisResponse] {.
     rest, endpoint: "/eth/v1/beacon/genesis",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis

proc getGenesisPlain*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/genesis",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getGenesis

proc getStateRoot*(state_id: StateIdent): RestResponse[GetStateRootResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/root",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateRoot

proc getStateFork*(state_id: StateIdent): RestResponse[GetStateForkResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/fork",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFork

proc getStateForkPlain*(state_id: StateIdent): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/fork",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFork

proc getStateFinalityCheckpoints*(state_id: StateIdent
          ): RestResponse[GetStateFinalityCheckpointsResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateFinalityCheckpoints

proc getStateValidators*(state_id: StateIdent,
                         id: seq[ValidatorIdent]
                        ): RestResponse[GetStateValidatorsResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/validators",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators

proc getStateValidator*(state_id: StateIdent,
                        validator_id: ValidatorIdent
                       ): RestResponse[GetStateValidatorResponse] {.
     rest,
     endpoint: "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidator

proc getStateValidatorPlain*(state_id: StateIdent,
                        validator_id: ValidatorIdent
                       ): RestPlainResponse {.
     rest,
     endpoint: "/eth/v1/beacon/states/{state_id}/validators/{validator_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidator

proc getStateValidatorBalances*(state_id: StateIdent
                        ): RestResponse[GetStateValidatorBalancesResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/validator_balances",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateValidators

proc getEpochCommittees*(state_id: StateIdent, epoch: Option[Epoch],
                        ): RestResponse[GetEpochCommitteesResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/committees",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochCommittees

proc getEpochSyncCommittees*(state_id: StateIdent, epoch: Option[Epoch],
                        ): RestResponse[GetEpochSyncCommitteesResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/sync_committees",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getEpochSyncCommittees

proc getBlockHeaders*(slot: Option[Slot], parent_root: Option[Eth2Digest]
                        ): RestResponse[GetBlockHeadersResponse] {.
     rest, endpoint: "/eth/v1/beacon/headers",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeaders

proc getBlockHeader*(block_id: BlockIdent): RestResponse[GetBlockHeaderResponse] {.
     rest, endpoint: "/eth/v1/beacon/headers/{block_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader

proc publishBlock*(body: phase0.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock

proc publishBlock*(body: altair.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock

proc publishBlock*(body: bellatrix.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock

proc getBlockPlain*(block_id: BlockIdent): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blocks/{block_id}",
     accept: preferSSZ,
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlock

proc getBlock*(client: RestClientRef, block_id: BlockIdent,
               restAccept = ""): Future[ForkedSignedBeaconBlock] {.async.} =
  let resp =
    if len(restAccept) > 0:
      await client.getBlockPlain(block_id, restAcceptType = restAccept)
    else:
      await client.getBlockPlain(block_id)
  let data =
    case resp.status
    of 200:
      case resp.contentType
      of "application/json":
        let blck =
          block:
            let res = decodeBytes(GetBlockResponse, resp.data,
                                  resp.contentType)
            if res.isErr():
              raise newException(RestError, $res.error())
            res.get()
        ForkedSignedBeaconBlock.init(blck.data)
      of "application/octet-stream":
        let blck =
          block:
            let res = decodeBytes(GetPhase0BlockSszResponse, resp.data,
                                  resp.contentType)
            if res.isErr():
              raise newException(RestError, $res.error())
            res.get()
        ForkedSignedBeaconBlock.init(blck)
      else:
        raise newException(RestError, "Unsupported content-type")
    of 400, 404, 500:
      raiseGenericError(resp)
    else:
      raiseUnknownStatusError(resp)
  return data

proc getBlockV2Plain*(block_id: BlockIdent): RestPlainResponse {.
     rest, endpoint: "/eth/v2/beacon/blocks/{block_id}",
     accept: preferSSZ,
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockV2

proc getBlockV2*(client: RestClientRef, block_id: BlockIdent,
                 cfg: RuntimeConfig,
                 restAccept = ""): Future[Option[ref ForkedSignedBeaconBlock]] {.
     async.} =
  # Return the asked-for block, or None in case 404 is returned from the server.
  # Raises on other errors
  let resp =
    if len(restAccept) > 0:
      await client.getBlockV2Plain(block_id, restAcceptType = restAccept)
    else:
      await client.getBlockV2Plain(block_id)

  return
    case resp.status
    of 200:
      case resp.contentType
      of "application/json":
        let blck =
          block:
            let res = decodeBytes(GetBlockV2Response, resp.data,
                                  resp.contentType)
            if res.isErr():
              raise newException(RestError, $res.error())
            newClone(res.get())
        some blck
      of "application/octet-stream":
        try:
          some newClone(readSszForkedSignedBeaconBlock(cfg, resp.data))
        except CatchableError as exc:
          raise newException(RestError, exc.msg)
      else:
        raise newException(RestError, "Unsupported content-type")
    of 404:
      none(ref ForkedSignedBeaconBlock)

    of 400, 500:
      let error =
        block:
          let res = decodeBytes(RestGenericError, resp.data, resp.contentType)
          if res.isErr():
            let msg = "Incorrect response error format (" & $resp.status &
                      ") [" & $res.error() & "]"
            raise newException(RestError, msg)
          res.get()
      let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
      raise newException(RestError, msg)
    else:
      let msg = "Unknown response status error (" & $resp.status & ")"
      raise newException(RestError, msg)

proc getBlockRoot*(block_id: BlockIdent): RestResponse[GetBlockRootResponse] {.
     rest, endpoint: "/eth/v1/beacon/blocks/{block_id}/root",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot

proc getBlockAttestations*(block_id: BlockIdent
                        ): RestResponse[GetBlockAttestationsResponse] {.
     rest, endpoint: "/eth/v1/beacon/blocks/{block_id}/attestations",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockAttestations

proc getPoolAttestations*(
    slot: Option[Slot],
    committee_index: Option[CommitteeIndex]
              ): RestResponse[GetPoolAttestationsResponse] {.
     rest, endpoint: "/eth/v1/beacon/pool/attestations",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolAttestations

proc submitPoolAttestations*(body: seq[Attestation]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/pool/attestations",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttestations

proc getPoolAttesterSlashings*(): RestResponse[GetPoolAttesterSlashingsResponse] {.
     rest, endpoint: "/eth/v1/beacon/pool/attester_slashings",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolAttesterSlashings

proc submitPoolAttesterSlashings*(body: AttesterSlashing): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/pool/attester_slashings",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolAttesterSlashings

proc getPoolProposerSlashings*(): RestResponse[GetPoolProposerSlashingsResponse] {.
     rest, endpoint: "/eth/v1/beacon/pool/proposer_slashings",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolProposerSlashings

proc submitPoolProposerSlashings*(body: ProposerSlashing): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/pool/proposer_slashings",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolProposerSlashings

proc submitPoolSyncCommitteeSignatures*(body: seq[RestSyncCommitteeMessage]): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/pool/sync_committees",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolSyncCommitteeSignatures

proc getPoolVoluntaryExits*(): RestResponse[GetPoolVoluntaryExitsResponse] {.
     rest, endpoint: "/eth/v1/beacon/pool/voluntary_exits",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getPoolVoluntaryExits

proc submitPoolVoluntaryExit*(body: SignedVoluntaryExit): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/pool/voluntary_exits",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/submitPoolVoluntaryExit
