# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos, presto/client, chronicles,
  ".."/".."/validators/slashing_protection_common,
  ".."/datatypes/[phase0, altair, bellatrix],
  ".."/mev/bellatrix_mev,
  ".."/[helpers, forks, keystore, eth2_ssz_serialization],
  "."/[rest_types, rest_common, eth2_rest_serialization]

from ".."/datatypes/capella import SignedBeaconBlock

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

proc getStateValidatorsPlain*(
       state_id: StateIdent,
       id: seq[ValidatorIdent]
     ): RestPlainResponse {.
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

proc getStateRandao*(state_id: StateIdent
             ): RestResponse[GetStateRandaoResponse] {.
     rest, endpoint: "/eth/v1/beacon/states/{state_id}/randao",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getStateRandao

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

# proc getBlockHeader*(block_id: BlockIdent): RestResponse[GetBlockHeaderResponse] {.
#      rest, endpoint: "/eth/v1/beacon/headers/{block_id}",
#      meth: MethodGet.}
#   ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader

proc getBlockHeaderPlain*(block_id: BlockIdent): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/headers/{block_id}",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader

proc getBlockHeader*(
       client: RestClientRef,
       block_id: BlockIdent
     ): Future[Opt[GetBlockHeaderResponse]] {.async.} =
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockHeader
  let resp = await client.getBlockHeaderPlain(block_id)
  return
    case resp.status
    of 200:
      let response = decodeBytes(GetBlockHeaderResponse, resp.data,
                                 resp.contentType).valueOr:
        raise newException(RestError, $error)
      Opt.some(response)
    of 404:
      Opt.none(GetBlockHeaderResponse)
    of 400, 500:
      let error = decodeBytes(RestErrorMessage, resp.data,
                              resp.contentType).valueOr:
        let msg = "Incorrect response error format (" & $resp.status &
                  ") [" & $error & "]"
        raise (ref RestResponseError)(msg: msg, status: resp.status)
      let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
      raise (ref RestResponseError)(
        msg: msg, status: error.code, message: error.message)
    else:
      raiseRestResponseError(resp)

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

proc publishBlock*(body: capella.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock

proc publishBlock*(body: DenebSignedBlockContents): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock

proc publishSszBlock*(
       client: RestClientRef,
       blck: ForkySignedBeaconBlock
     ): Future[RestPlainResponse] {.async.} =
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlock
  let
    consensus = typeof(blck).kind.toString()
    resp = await client.publishBlock(
      blck, restContentType = $OctetStreamMediaType,
      extraHeaders = @[("eth-consensus-version", consensus)])
  return resp

proc publishBlockV2Plain(body: phase0.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v2/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlockV2

proc publishBlockV2Plain(body: altair.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v2/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlockV2

proc publishBlockV2Plain(body: bellatrix.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v2/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlockV2

proc publishBlockV2Plain(body: capella.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v2/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlockV2

proc publishBlockV2Plain(body: DenebSignedBlockContents): RestPlainResponse {.
     rest, endpoint: "/eth/v2/beacon/blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlockV2

proc publishBlockV2*(
       client: RestClientRef,
       blck: phase0.SignedBeaconBlock | altair.SignedBeaconBlock |
       bellatrix.SignedBeaconBlock | capella.SignedBeaconBlock |
       deneb.SignedBeaconBlock
     ): Future[RestPlainResponse] {.async} =
  let
    consensus = typeof(blck).kind.toString()
    resp = await client.publishBlockV2Plain(
      blck, extraHeaders = @[
        ("eth-consensus-version", consensus),
        ("broadcast_validation", "gossip")])
  return resp

proc publishBlindedBlock*(body: phase0.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blinded_blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlindedBlock

proc publishBlindedBlock*(body: altair.SignedBeaconBlock): RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blinded_blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlindedBlock

proc publishBlindedBlock*(body: bellatrix_mev.SignedBlindedBeaconBlock):
       RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blinded_blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlindedBlock

proc publishBlindedBlock*(body: capella_mev.SignedBlindedBeaconBlock):
       RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blinded_blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlindedBlock

proc publishBlindedBlock*(body: deneb_mev.SignedBlindedBeaconBlock):
       RestPlainResponse {.
     rest, endpoint: "/eth/v1/beacon/blinded_blocks",
     meth: MethodPost.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlindedBlock

proc publishSszBlindedBlock*(
       client: RestClientRef,
       blck: ForkySignedBeaconBlock
     ): Future[RestPlainResponse] {.async.} =
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/publishBlindedBlock
  let
    consensus = typeof(blck).kind.toString()
    resp = await client.publishBlindedBlock(
      blck, restContentType = $OctetStreamMediaType,
      extraHeaders = @[("eth-consensus-version", consensus)])
  return resp

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
      if resp.contentType.isNone() or
         isWildCard(resp.contentType.get().mediaType):
        raise newException(RestError, "Missing or incorrect Content-Type")
      else:
        let mediaType = resp.contentType.get().mediaType
        if mediaType == ApplicationJsonMediaType:
          let blck = decodeBytes(GetBlockV2Response, resp.data,
                                 resp.contentType).valueOr:
            raise newException(RestError, $error)
          some(newClone(blck))
        elif mediaType == OctetStreamMediaType:
          try:
            some newClone(readSszForkedSignedBeaconBlock(cfg, resp.data))
          except CatchableError as exc:
            raise newException(RestError, exc.msg)
        else:
          raise newException(RestError, "Unsupported Content-Type")
    of 404:
      none(ref ForkedSignedBeaconBlock)
    of 400, 500:
      let error = decodeBytes(RestErrorMessage, resp.data,
                              resp.contentType).valueOr:
        let msg = "Incorrect response error format (" & $resp.status &
                  ") [" & $error & "]"
        raise (ref RestResponseError)(msg: msg, status: resp.status)
      let msg = "Error response (" & $resp.status & ") [" & error.message & "]"
      raise (ref RestResponseError)(
        msg: msg, status: error.code, message: error.message)
    else:
      raiseRestResponseError(resp)

proc getBlockRoot*(block_id: BlockIdent): RestResponse[GetBlockRootResponse] {.
     rest, endpoint: "/eth/v1/beacon/blocks/{block_id}/root",
     meth: MethodGet.}
  ## https://ethereum.github.io/beacon-APIs/#/Beacon/getBlockRoot

proc getBlockRootPlain*(block_id: BlockIdent): RestPlainResponse {.
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

proc getDepositSnapshot*(): RestResponse[GetDepositSnapshotResponse] {.
     rest, endpoint: "/eth/v1/beacon/deposit_snapshot",
     meth: MethodGet.}
  ## https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4881.md
