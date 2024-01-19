# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/typetraits,
  results,
  ../spec/datatypes/base

from ../spec/eth2_apis/dynamic_fee_recipients import
  DynamicFeeRecipientsStore, getDynamicFeeRecipient
from ../validators/keystore_management import
     getPerValidatorDefaultFeeRecipient, getSuggestedGasLimit,
     getSuggestedFeeRecipient
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
