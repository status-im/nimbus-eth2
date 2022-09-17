import
  std/tables,
  stew/results,
  chronicles,
  web3/ethtypes,
  ../datatypes/base

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
  info "Updating fee recipient",
    validator, feeRecipient = feeRecipient.toHex(), currentEpoch
  store.mappings[validator] = Entry(recipient: feeRecipient,
                                    addedAt: currentEpoch)

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
