# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  ../crypto,
  ../datatypes/[base, constants]

const
  # https://github.com/ethereum/builder-specs/blob/5aef563dc3532a5009fef02bae97ca563ec28e5b/specs/gloas/builder.md#constants
  DOMAIN_BUILDER_REQUEST_AUTH* = DomainType([byte 0x0b, 0x00, 0x00, 0x01])
  MAX_BUILDER_AUTH_DATA_SIZE: int64 = 4096

  # https://github.com/ethereum/beacon-APIs/blob/e76cf1c173be80101e130266cd08f9a108442a97/types/gloas/builder_entry.yaml
  MAX_BUILDER_ENTRIES*: int64 = 64
  MAX_BUILDER_URL_SIZE*: int64 = 2048
  MAX_BUILDER_PUBKEYS*: int64 = 64

type
  BuilderRequestAuthData* = List[byte, Limit MAX_BUILDER_AUTH_DATA_SIZE]

  # https://github.com/ethereum/builder-specs/blob/5aef563dc3532a5009fef02bae97ca563ec28e5b/specs/gloas/validator.md#builderrequestauth
  BuilderRequestAuth* = object
    data*: BuilderRequestAuthData
    slot*: Slot

  # https://github.com/ethereum/builder-specs/blob/5aef563dc3532a5009fef02bae97ca563ec28e5b/specs/gloas/validator.md#signedbuilderrequestauth
  SignedBuilderRequestAuth* = object
    message*: BuilderRequestAuth
    signature*: ValidatorSig

  # https://github.com/ethereum/builder-specs/blob/5aef563dc3532a5009fef02bae97ca563ec28e5b/specs/gloas/validator.md#builderpreferences
  BuilderPreferences* = object
    max_execution_payment*: Gwei

  # https://github.com/ethereum/builder-specs/blob/5aef563dc3532a5009fef02bae97ca563ec28e5b/specs/gloas/validator.md#builderpreferences
  BuilderPreferencesRequest* = object
    preferences*: BuilderPreferences
    auth*: SignedBuilderRequestAuth

  # https://github.com/ethereum/keymanager-APIs/blob/d1c9bb46914be4e80f0cd7d5a225695ba94d8751/types/builder_entry.yaml#L54-L137
  BuilderEntry* = object
    url*: List[byte, Limit MAX_BUILDER_URL_SIZE]
    auth_data*: Opt[BuilderRequestAuthData]
    builder_pubkeys*: Opt[List[ValidatorPubKey, Limit MAX_BUILDER_PUBKEYS]]
    max_execution_payment*: Opt[Gwei]
    min_bid*: Opt[Gwei]
    builder_boost_factor*: Opt[uint64]

  # https://github.com/ethereum/keymanager-APIs/blob/d1c9bb46914be4e80f0cd7d5a225695ba94d8751/types/builder_entry.yaml#L1-L52
  BuilderConfig* = object
    min_bid*: Opt[Gwei]
    builder_boost_factor*: Opt[uint64]
    builders*: Opt[List[BuilderEntry, Limit MAX_BUILDER_ENTRIES]]

  ResolvedBuilderEntry* = object
    url*: List[byte, Limit MAX_BUILDER_URL_SIZE]
    auth_data*: BuilderRequestAuthData
    builder_pubkeys*: List[ValidatorPubKey, Limit MAX_BUILDER_PUBKEYS]
    max_execution_payment*: Gwei
    min_bid*: Gwei
    builder_boost_factor*: uint64

  ResolvedBuilderConfig* = object
    min_bid*: Gwei
    builder_boost_factor*: uint64
    builders*: List[BuilderEntry, Limit MAX_BUILDER_ENTRIES]

  # https://github.com/ethereum/beacon-APIs/blob/e76cf1c173be80101e130266cd08f9a108442a97/types/gloas/builder_entry.yaml
  BuilderEntryForSlot* = object
    url*: List[byte, Limit MAX_BUILDER_URL_SIZE]
    auth*: SignedBuilderRequestAuth
    builder_pubkeys*: List[ValidatorPubKey, Limit MAX_BUILDER_PUBKEYS]
    max_execution_payment*: Gwei
    min_bid*: Gwei
    builder_boost_factor*: uint64

  BuilderConfigForSlot* = object
    min_bid*: Gwei
    builder_boost_factor*: uint64
    builders*: List[BuilderEntryForSlot, Limit MAX_BUILDER_ENTRIES]
