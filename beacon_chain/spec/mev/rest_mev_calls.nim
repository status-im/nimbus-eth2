# beacon_chain
# Copyright (c) 2024-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos, presto/client,
  ".."/eth2_apis/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc getStatus*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/builder/status",
     meth: MethodGet.}
  ## https://ethereum.github.io/builder-specs/#/Builder/status

proc registerValidator*(body: seq[SignedValidatorRegistrationV1]
                       ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/builder/validators",
     meth: MethodPost, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.4.0/apis/builder/validators.yaml
  ## https://github.com/ethereum/beacon-APIs/blob/v2.3.0/apis/validator/register_validator.yaml

proc getHeaderPlain*(
    slot: Slot,
    parent_hash: Eth2Digest,
    pubkey: ValidatorPubKey
): RestPlainResponse {.
  rest, endpoint: "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}",
  meth: MethodGet, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.4.0/apis/builder/header.yaml

proc getHeader*(
    client: RestClientRef,
    slot: Slot,
    parent_hash: Eth2Digest,
    pubkey: ValidatorPubKey
): Future[RestPlainResponse] {.
  async: (raises: [CancelledError, RestEncodingError, RestDnsResolveError,
                   RestCommunicationError], raw: true).} =
  client.getHeaderPlain(
    slot, parent_hash, pubkey,
    restAcceptType = "application/octet-stream,application/json;q=0.5",
  )

proc submitBlindedBlockPlain*(
    body: electra_mev.SignedBlindedBeaconBlock
): RestPlainResponse {.
  rest, endpoint: "/eth/v1/builder/blinded_blocks",
  meth: MethodPost, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.5.0/apis/builder/blinded_blocks.yaml

proc submitBlindedBlockV2Plain*(
    body: fulu_mev.SignedBlindedBeaconBlock
): RestPlainResponse {.
  rest, endpoint: "/eth/v2/builder/blinded_blocks",
  meth: MethodPost, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/ae1d97d080a12bfb7ca248b58fb1fc6b10aed02e/apis/builder/blinded_blocks_v2.yaml

proc submitBlindedBlock*(
    client: RestClientRef,
    body: electra_mev.SignedBlindedBeaconBlock
): Future[RestPlainResponse] {.
  async: (raises: [CancelledError, RestEncodingError, RestDnsResolveError,
                   RestCommunicationError], raw: true).} =
  client.submitBlindedBlockPlain(
    body,
    restAcceptType = "application/octet-stream,application/json;q=0.5",
    extraHeaders = @[("eth-consensus-version", toString(typeof(body).kind))]
  )

proc submitBlindedBlock*(
    client: RestClientRef,
    body: fulu_mev.SignedBlindedBeaconBlock
): Future[RestPlainResponse] {.
  async: (raises: [CancelledError, RestEncodingError, RestDnsResolveError,
                   RestCommunicationError], raw: true).} =
  # Everyone should have upgraded by the time of fulu
  client.submitBlindedBlockV2Plain(
    body,
    restAcceptType = "application/octet-stream,application/json;q=0.5",
    extraHeaders = @[("eth-consensus-version", toString(typeof(body).kind))]
  )
