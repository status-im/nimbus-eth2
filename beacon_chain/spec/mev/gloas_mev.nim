# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  ssz_serialization/types,
  ".."/crypto,
  ".."/datatypes/[base, constants]

const
  # https://github.com/ethereum/builder-specs/blob/main/specs/gloas/builder.md#constants
  MAX_EXECUTION_PAYMENT*: uint64 = (1 shl 64) - 1
  MAX_DATA_SIZE*: int64 = 4096
  DOMAIN_REQUEST_AUTH* = DomainType([byte 0x0B, 0x00, 0x00, 0x01])

type
  # https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#requestauthv1
  RequestAuthV1* = object
    data*: List[byte, Limit MAX_DATA_SIZE]
    slot*: Slot

  # https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#signedrequestauthv1
  SignedRequestAuthV1* = object
    message*: RequestAuthV1
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#builderpreferencesv1
  BuilderPreferencesV1* = object
    max_execution_payment*: Gwei

  # https://github.com/ethereum/builder-specs/blob/main/specs/gloas/validator.md#builderpreferencesrequestv1
  BuilderPreferencesRequestV1* = object
    preferences*: BuilderPreferencesV1
    auth*: SignedRequestAuthV1
