# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  chronos, presto/client,
  ".."/eth2_apis/[rest_types, eth2_rest_serialization]

export chronos, client, rest_types, eth2_rest_serialization

proc registerValidator*(body: seq[SignedValidatorRegistrationV1]
                       ): RestPlainResponse {.
     rest, endpoint: "/eth/v1/builder/validators",
     meth: MethodPost.}
  ## https://github.com/ethereum/builder-specs/blob/v0.2.0/apis/builder/validators.yaml
  ## https://github.com/ethereum/beacon-APIs/blob/master/apis/validator/register_validator.yaml

proc getHeader*(slot: Slot,
                parent_hash: Eth2Digest,
                pubkey: ValidatorPubKey
               ): RestResponse[GetHeaderResponse] {.
     rest, endpoint: "/eth/v1/builder/header/{slot}/{parent_hash}/{pubkey}",
     meth: MethodGet.}
  ## https://github.com/ethereum/builder-specs/blob/v0.2.0/apis/builder/header.yaml

proc submitBlindedBlock*(body: SignedBlindedBeaconBlock
                        ): RestResponse[SubmitBlindedBlockResponse] {.
     rest, endpoint: "/eth/v1/builder/blinded_blocks",
     meth: MethodPost.}
  ## https://github.com/ethereum/builder-specs/blob/v0.2.0/apis/builder/blinded_blocks.yaml

proc checkBuilderStatus*(): RestPlainResponse {.
     rest, endpoint: "/eth/v1/builder/status",
     meth: MethodGet.}
  ## https://github.com/ethereum/builder-specs/blob/v0.2.0/apis/builder/status.yaml
