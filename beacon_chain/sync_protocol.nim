import
  rlp, asyncdispatch2, ranges/bitranges, eth_p2p, eth_p2p/rlpx,
  datatypes

type
  ValidatorChangeLogEntry* = object
    case kind*: ValidatorSetDeltaFlags
    of Entry:
      pubkey: BLSPublicKey
    else:
      index: uint32

  ValidatorSet = seq[ValidatorRecord]

protocol BeaconSync(version = 1):
  requestResponse:
    proc getValidatorChangeLog(peer: Peer, changeLogHead: Blake2_256_Digest)

    proc validatorChangeLog(peer: Peer,
                            signedBlock: BeaconBlock,
                            beaconState: BeaconState,
                            added: openarray[BLSPublicKey],
                            removed: openarray[uint32],
                            order: seq[byte])

template `++`(x: var int): int =
  let y = x
  inc x
  y

type
  # A bit shorter names for convenience
  ChangeLog = BeaconSync.validatorChangeLog
  ChangeLogEntry = ValidatorChangeLogEntry

iterator changes*(cl: ChangeLog): ChangeLogEntry =
  var
    bits = cl.added.len + cl.removed.len
    addedIdx = 0
    removedIdx = 0

  for i in 0 ..< bits:
    yield if order.getBit(i):
      ChangeLogEntry(kind: Entry, pubkey: added[addedIdx++])
    else:
      ChangeLogEntry(kind: Exit, index: removed[removedIdx++])

proc getValidatorChangeLog*(node: EthereumNode):
                            Future[(Peer, ChangeLog)] {.async.} =
  while true:
    let peer = node.randomPeerWith(BeaconSync):
    if peer == nil: return

    let res = await peer.getValidatorChangeLog(timeout = 1)
    if res.isSome:
      return (peer, res.get)

proc applyValidatorChangeLog*(changeLog: ChangeLog,
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

  outBeaconState.last_finalized_slot =
    changeLog.signedBlock.slot div CYCLE_LENGTH

  outBeaconState.validator_set_delta_hash_chain =
    changeLog.beaconState.validator_set_delta_hash_chain

