{.push raises: [].}

import
  std/[os, times],
  chronos,
  stew/io2,
  ./spec/datatypes/[altair, bellatrix, phase0],
  ./spec/deposit_snapshots,
  ./validators/[keystore_management, beacon_validators],
  "."/[
    beacon_node,
    nimbus_binary_common]

from ./spec/datatypes/deneb import SignedBeaconBlock

import libp2p/protocols/pubsub/gossipsub

proc initFullNode(
    node: BeaconNode,
    getBeaconTime: GetBeaconTimeFn) {.async.} =
  node.router = new MessageRouter

  await node.addValidators()

from "."/consensus_object_pools/blockchain_dag import preInit
from "."/consensus_object_pools/block_pools_types import ChainDAGRef

proc init*(T: type BeaconNode,
           config: BeaconNodeConf,
           metadata: Eth2NetworkMetadata): Future[BeaconNode]
          {.async.} =
  template cfg: auto = metadata.cfg
  template eth1Network: auto = metadata.eth1Network

  let
    db = BeaconChainDB.new(config.databaseDir, cfg, inMemory = false)

  let checkpointState = if config.finalizedCheckpointState.isSome:
    let checkpointStatePath = config.finalizedCheckpointState.get.string
    let tmp = try:
      newClone(readSszForkedHashedBeaconState(
        cfg, readAllBytes(checkpointStatePath).tryGet()))
    except SszError as err:
      quit 1
    except CatchableError as err:
      quit 1

    if not getStateField(tmp[], slot).is_epoch:
      quit 1
    tmp
  else:
    nil

  if config.finalizedDepositTreeSnapshot.isSome:
    let
      depositTreeSnapshotPath = config.finalizedDepositTreeSnapshot.get.string
      depositTreeSnapshot = try:
        SSZ.loadFile(depositTreeSnapshotPath, DepositTreeSnapshot)
      except SszError as err:
        quit 1
      except CatchableError as err:
        quit 1

  var networkGenesisValidatorsRoot = metadata.bakedGenesisValidatorsRoot

  var genesisState = checkpointState
  if true:
    genesisState = if checkpointState != nil and getStateField(checkpointState[], slot) == 0:
      checkpointState
    else:
      let genesisBytes = block:
        if metadata.genesis.kind != BakedIn and config.genesisState.isSome:
          let res = io2.readAllBytes(config.genesisState.get.string)
          res.valueOr:
            quit 1
        elif metadata.hasGenesis:
          try:
            metadata.fetchGenesisBytes()
          except CatchableError as err:
            quit 1
        else:
          @[]

      if genesisBytes.len > 0:
        try:
          newClone readSszForkedHashedBeaconState(cfg, genesisBytes)
        except CatchableError as err:
          quit 1
      else:
        nil

    if genesisState == nil and checkpointState == nil:
      quit 1

    if not genesisState.isNil and not checkpointState.isNil:
      if getStateField(genesisState[], genesis_validators_root) !=
          getStateField(checkpointState[], genesis_validators_root):
        quit 1

    try:
      if not genesisState.isNil:
        networkGenesisValidatorsRoot =
          Opt.some(getStateField(genesisState[], genesis_validators_root))

      if not checkpointState.isNil:
        if genesisState.isNil or
            getStateField(checkpointState[], slot) != GENESIS_SLOT:
          ChainDAGRef.preInit(checkpointState[])
    except CatchableError as exc:
      quit 1
  else:
    if not checkpointState.isNil:
      quit 1

  doAssert not genesisState.isNil

  let
    genesisTime = getStateField(genesisState[], genesis_time)
    beaconClock = BeaconClock.init(genesisTime).valueOr:
      quit 1

    getBeaconTime = beaconClock.getBeaconTimeFn()

  let elManager = default(ELManager)

  let
    keystoreCache = KeystoreCacheRef.init()
    validatorPool = new ValidatorPool

  let node = BeaconNode(
    config: config,
    attachedValidators: validatorPool,
    elManager: elManager,
    keystoreCache: keystoreCache,
    beaconClock: beaconClock,
    cfg: cfg,
    genesisState: genesisState)

  await node.initFullNode(getBeaconTime)

  node

from "."/consensus_object_pools/block_dag import BlockRef, init

func getBlockRef2(root: Eth2Digest): Opt[BlockRef] =
  let newRef = BlockRef.init(
    root,
    0.Slot)
  return ok(newRef)

proc start*(node: BeaconNode) {.raises: [CatchableError].} =
  echo "foo"
  node.elManager.start()
  let
    wallTime = node.beaconClock.now()

  asyncSpawn runSlotLoop(node, wallTime)

  while true:
    poll()
