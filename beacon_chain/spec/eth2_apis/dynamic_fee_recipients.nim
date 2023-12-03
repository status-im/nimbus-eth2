# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/tables,
  stew/results,
  chronicles,
  ../datatypes/base

logScope: topics = "fee_recipient"

type
  Entry = object
    recipient: Eth1Address
    addedAt: Epoch

  DynamicFeeRecipientsStore* = object
    mappings: Table[ValidatorIndex, Entry]

func init*(T: type DynamicFeeRecipientsStore): T =
  T(mappings: initTable[ValidatorIndex, Entry]())

proc addMapping*(store: var DynamicFeeRecipientsStore,
                 validator: ValidatorIndex,
                 feeRecipient: Eth1Address,
                 currentEpoch: Epoch) =
  var updated = false
  store.mappings.withValue(validator, entry) do:
    updated = not (entry[].recipient == feeRecipient)
    entry[] = Entry(recipient: feeRecipient, addedAt: currentEpoch)
  do:
    updated = true
    store.mappings[validator] = Entry(recipient: feeRecipient,
                                      addedAt: currentEpoch)
  if updated:
    info "Updating fee recipient",
      validator, feeRecipient = feeRecipient.toHex(), currentEpoch
  else:
    debug "Refreshing fee recipient",
      validator, feeRecipient = feeRecipient.toHex(), currentEpoch

func getDynamicFeeRecipient*(store: var DynamicFeeRecipientsStore,
                             validator: ValidatorIndex,
                             currentEpoch: Epoch): Opt[Eth1Address] =
  store.mappings.withValue(validator, entry) do:
    # https://ethereum.github.io/beacon-APIs/#/ValidatorRequiredApi/prepareBeaconProposer
    #
    # The information supplied for each validator index will persist
    # through the epoch in which the call is submitted and for a further
    # two epochs after that, or until the beacon node restarts.
    #
    # It is expected that validator clients will send this information
    # periodically, for example each epoch, to ensure beacon nodes have
    # correct and timely fee recipient information.
    return if (currentEpoch - entry.addedAt) > 2:
      err()
    else:
      ok entry.recipient
  do:
    return err()

func pruneOldMappings*(store: var DynamicFeeRecipientsStore,
                       currentEpoch: Epoch) =
  var toPrune: seq[ValidatorIndex]

  for idx, entry in store.mappings:
    if (currentEpoch - entry.addedAt) > 2:
      toPrune.add idx

  for idx in toPrune:
    store.mappings.del idx
