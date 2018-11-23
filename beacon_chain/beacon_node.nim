import
  os, net,
  asyncdispatch2, confutils, eth_p2p, eth_keys,
  conf, datatypes, time, beacon_chain_db, validator_pool,
  sync_protocol, gossipsub_protocol, trusted_state_snapshots,
  private/helpers

type
  BeaconNode* = ref object
    beaconState*: BeaconState
    network*: EthereumNode
    db*: BeaconChainDB
    config*: Configuration
    keys*: KeyPair
    attachedValidators: Table[BLSPublicKey, AttachedValidator]

const
  version = "v0.1" # read this from the nimble file
  clientId = "nimbus beacon node " & version
  topicBeaconBlocks = "ethereum/2.1/beacon_blocks"

proc ensureNetworkKeys*(dataDir: string): KeyPair =
  # TODO:
  # 1. Check if keys already exist in the data dir
  # 2. Generate new ones and save them in the directory
  # if necessary
  return newKeyPair()

proc init*(T: type BeaconNode, conf: Configuration): T =
  new result
  result.config = conf
  result.db = BeaconChainDB.init(conf.dataDir)
  result.keys = ensureNetworkKeys(conf.dataDir)

  var address: Address
  address.ip = parseIpAddress("0.0.0.0")
  address.tcpPort = Port(conf.tcpPort)
  address.udpPort = Port(conf.udpPort)
  result.network = newEthereumNode(result.keys, address, 0, nil, clientId)

proc sync*(node: BeaconNode): Future[bool] {.async.} =
  let persistedState = node.db.lastFinalizedState()
  if persistedState.isNil or
     persistedState[].slotDistanceFromNow() > WITHDRAWAL_PERIOD:
    node.beaconState = await obtainTrustedStateSnapshot(node.db)
  else:
    node.beaconState = persistedState[]
    var targetSlot = toSlot timeSinceGenesis(node.beaconState)

    while node.beaconState.last_finalized_slot < targetSlot:
      var (peer, changeLog) = node.network.getValidatorChangeLog(
        node.beaconState.validator_set_delta_hash_chain)

      if peer == nil:
        error "Failed to sync with any peer"
        return false

      if applyValidatorChangeLog(changeLog, node.beaconState):
        node.db.persistBlock(changeLog.signedBlock, node.beaconState)
      else:
        warn "Ignoring invalid validator change log", sentFrom = peer

  return true

proc addLocalValidators*(node: BeaconNode) =
  for validator in node.config.validatorKeys:
    # TODO:
    # 1. Parse the validator keys
    #
    # 2. Check whether the validators exist in the beacon state.
    #    (Report a warning otherwise)
    #
    # 3. Add the validators to node.attachedValidators
    discard

proc scheduleCycleActions(node: BeaconNode)
  ## This schedules the required block proposals and
  ## attestations from our attached validators.
  let cycle_start = node.last_state_recalculation_slot

  # Schedule block proposals
  for i in 0 ..< CYCLE_LENGTH:
    let
      proposer_idx = get_beacon_proposer_idx(node.beaconState, cycle_start + i)
      proposer_key = node.beaconState.validators[proposer_idx].pubkey
      attached_validator = node.attachedValidators.getAttachedValidator(proposer_key)
    
    if attached_validator != nil:
      proc proposeBlock =
        # TODO
        discard

      # TODO:
      # Warm-up the proposer earlier to try to obtain previous
      # missing blocks if necessary

      addTimer slotMiddle(cycle_start + i), proposeBlock

  # Schedule attestations
  # TODO:
  # Similar to the above, but using `get_shard_and_committees_idx`

proc processBlocks*(node: BeaconNode) {.async.} =
  node.scheduleCycleActions()

  node.network.subscribe(topicBeaconBlocks) do (b: BeaconBlock):
    # TODO:
    #
    # 1. Check for missing blocks and obtain them

    if b.slot mod CYCLE_LENGTH == 0:
      node.scheduleCycleActions()

when isMainModule:
  let conf = Configuration.load()
  waitFor syncrhronizeClock()
  var node = BeaconNode.init conf

  if not waitFor node.sync():
    quit 1

  node.addLocalValidators()

  waitFor node.processBlocks()

