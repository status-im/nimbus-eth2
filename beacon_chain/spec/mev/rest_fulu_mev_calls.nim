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

proc getHeaderFuluPlain*(
    slot: Slot,
    parent_hash: Eth2Digest,
    pubkey: ValidatorPubKey
): RestPlainResponse {.
  rest, endpoint: "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}",
  meth: MethodGet, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.4.0/apis/builder/header.yaml

proc getHeaderFulu*(
    client: RestClientRef,
    slot: Slot,
    parent_hash: Eth2Digest,
    pubkey: ValidatorPubKey
): Future[RestPlainResponse] {.
  async: (raises: [CancelledError, RestEncodingError, RestDnsResolveError,
                   RestCommunicationError], raw: true).} =
  client.getHeaderFuluPlain(
    slot, parent_hash, pubkey,
    restAcceptType = "application/octet-stream,application/json;q=0.5",
  )

proc submitBlindedBlockPlain*(
    body: fulu_mev.SignedBlindedBeaconBlock
): RestPlainResponse {.
  rest, endpoint: "/eth/v2/builder/blinded_blocks",
  meth: MethodPost, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.4.0/apis/builder/blinded_blocks.yaml

proc submitBlindedBlock*(
  client: RestClientRef,
  body: fulu_mev.SignedBlindedBeaconBlock
): Future[RestPlainResponse] {.
  async: (raises: [CancelledError, RestEncodingError, RestDnsResolveError,
                   RestCommunicationError], raw: true).} =
  ## https://github.com/ethereum/builder-specs/blob/v0.4.0/apis/builder/blinded_blocks.yaml
  client.submitBlindedBlockPlain(
    body,
    restAcceptType = "application/octet-stream,application/json;q=0.5",
    extraHeaders = @[("eth-consensus-version", toString(ConsensusFork.Fulu))]
  )
