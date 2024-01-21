# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronos, presto/client,
  ".."/eth2_apis/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc registerValidator*(body: seq[SignedValidatorRegistrationV1]
                       ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/builder/validators",
     meth: MethodPost, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.3.0/apis/builder/validators.yaml
  ## https://github.com/ethereum/beacon-APIs/blob/v2.3.0/apis/validator/register_validator.yaml

proc getHeaderCapella*(slot: Slot,
                       parent_hash: Eth2Digest,
                       pubkey: ValidatorPubKey
                      ): RestResponse[GetHeaderResponseCapella] {.
     rest, endpoint: "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}",
     meth: MethodGet, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.3.0/apis/builder/header.yaml

proc submitBlindedBlock*(body: capella_mev.SignedBlindedBeaconBlock
                        ): RestResponse[SubmitBlindedBlockResponseCapella] {.
     rest, endpoint: "/eth/v1/builder/blinded_blocks",
     meth: MethodPost, connection: {Dedicated, Close}.}
  ## https://github.com/ethereum/builder-specs/blob/v0.3.0/apis/builder/blinded_blocks.yaml
