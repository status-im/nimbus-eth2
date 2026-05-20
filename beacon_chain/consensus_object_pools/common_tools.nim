# beacon_chain
# Copyright (c) 2024-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/typetraits,
  results,
  ../spec/datatypes/base

from ../spec/eth2_apis/dynamic_fee_recipients import
  DynamicFeeRecipientsStore, getDynamicFeeRecipient
from ../validators/keystore_management import
     getPerValidatorDefaultFeeRecipient, getSuggestedGasLimit,
     getSuggestedFeeRecipient, getSuggestedGraffiti
from ../spec/beaconstate import has_eth1_withdrawal_credential
from ../spec/presets import Eth1Address

export Eth1Address, DynamicFeeRecipientsStore

proc getFeeRecipient*(
    dynamicFeeRecipientsStore: ref DynamicFeeRecipientsStore,
    pubkey: ValidatorPubKey,
    validatorIdx: Opt[ValidatorIndex],
    stateValidator: Opt[Validator],
    configFeeRecipient: Opt[Eth1Address],
    configValidatorsDir: string,
    epoch: Epoch
): Eth1Address =
  let dynFeeRecipient =
    if validatorIdx.isSome:
      dynamicFeeRecipientsStore[].getDynamicFeeRecipient(
        validatorIdx.get(), epoch)
    else:
      Opt.none(Eth1Address)

  dynFeeRecipient.valueOr:
    let
      withdrawalAddress =
        if stateValidator.isSome():
          let validator = stateValidator.get()
          if has_eth1_withdrawal_credential(validator):
            var address: distinctBase(Eth1Address)
            address[0 .. ^1] = validator.withdrawal_credentials.data[12 .. ^1]
            Opt.some Eth1Address(address)
          else:
            Opt.none Eth1Address
        else:
          Opt.none Eth1Address
      defaultFeeRecipient =
        getPerValidatorDefaultFeeRecipient(configFeeRecipient,
          withdrawalAddress)
    getSuggestedFeeRecipient(
      configValidatorsDir, pubkey, defaultFeeRecipient).valueOr:
      defaultFeeRecipient

proc getGasLimit*(configValidatorsDir: string,
                  configGasLimit: uint64,
                  pubkey: ValidatorPubKey): uint64 =
  getSuggestedGasLimit(configValidatorsDir, pubkey, configGasLimit).valueOr:
    configGasLimit

# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.8/specs/gloas/p2p-interface.md#is_gas_limit_target_compatible
func is_gas_limit_target_compatible*(
    parent_gas_limit, gas_limit, target_gas_limit: uint64): bool =
  ## Check if ``gas_limit`` is compatible with ``target_gas_limit`` under
  ## the EIP-1559 transition rule from ``parent_gas_limit``.
  let
    max_gas_limit_difference = max(parent_gas_limit div 1024, 1) - 1
    min_gas_limit = parent_gas_limit - max_gas_limit_difference
    max_gas_limit = parent_gas_limit + max_gas_limit_difference

  if target_gas_limit >= min_gas_limit and target_gas_limit <= max_gas_limit:
    return gas_limit == target_gas_limit
  if target_gas_limit > max_gas_limit:
    return gas_limit == max_gas_limit
  gas_limit == min_gas_limit

proc getGraffiti*(configValidatorsDir: string,
                  configGraffiti: GraffitiBytes,
                  pubkey: ValidatorPubKey): GraffitiBytes =
  getSuggestedGraffiti(configValidatorsDir, pubkey, configGraffiti).valueOr:
    configGraffiti
