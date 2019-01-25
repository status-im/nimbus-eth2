import
  options,
  chronicles, rlp, asyncdispatch2, ranges/bitranges, eth_p2p, eth_p2p/rlpx,
  spec/[datatypes, crypto, digest]

type
  ValidatorChangeLogEntry* = object
    case kind*: ValidatorSetDeltaFlags
    of Activation:
      pubkey: ValidatorPubKey
    else:
      index: uint32

  ValidatorSet = seq[Validator]

p2pProtocol BeaconSync(version = 1,
                       shortName = "bcs"):
  requestResponse:
    proc getValidatorChangeLog(peer: Peer, changeLogHead: Eth2Digest) =
      var bb: BeaconBlock
      var bs: BeaconState
      # TODO: get the changelog from the DB.
      await peer.validatorChangeLog(reqId, bb, bs, [], [], @[])

    proc validatorChangeLog(peer: Peer,
                            signedBlock: BeaconBlock,
                            beaconState: BeaconState,
                            added: openarray[ValidatorPubKey],
                            removed: openarray[uint32],
                            order: seq[byte])

type
  # A bit shorter names for convenience
  ChangeLog = BeaconSync.validatorChangeLog
  ChangeLogEntry = ValidatorChangeLogEntry

func validate*(log: ChangeLog): bool =
  # TODO:
  # Assert that the number of raised bits in log.order (a.k.a population count)
  # matches the number of elements in log.added
  # https://en.wikichip.org/wiki/population_count
  return true

iterator changes*(log: ChangeLog): ChangeLogEntry =
  var
    bits = log.added.len + log.removed.len
    addedIdx = 0
    removedIdx = 0

  template nextItem(collection): auto =
    let idx = `collection Idx`
    inc `collection Idx`
    log.collection[idx]

  for i in 0 ..< bits:
    yield if log.order.getBit(i):
      ChangeLogEntry(kind: Activation, pubkey: nextItem(added))
    else:
      ChangeLogEntry(kind: ValidatorSetDeltaFlags.Exit, index: nextItem(removed))

proc getValidatorChangeLog*(node: EthereumNode, changeLogHead: Eth2Digest):
                            Future[(Peer, ChangeLog)] {.async.} =
  while true:
    let peer = node.randomPeerWith(BeaconSync)
    if peer == nil: return

    let res = await peer.getValidatorChangeLog(changeLogHead, timeout = 1)
    if res.isSome:
      return (peer, res.get)

proc applyValidatorChangeLog*(log: ChangeLog,
                              outBeaconState: var BeaconState): bool =
  # TODO:
  #
  # 1. Validate that the signedBlock state root hash matches the
  #    provided beaconState
  #
  # 2. Validate that the applied changelog produces the correct
  #    new change log head
  #
  # 3. Check that enough signatures from the known validator set
  #    are present
  #
  # 4. Apply all changes to the validator set
  #

  outBeaconState.finalized_epoch =
    log.signedBlock.slot div EPOCH_LENGTH

  outBeaconState.validator_registry_delta_chain_tip =
    log.beaconState.validator_registry_delta_chain_tip

