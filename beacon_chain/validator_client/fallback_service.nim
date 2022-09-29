# beacon_chain
# Copyright (c) 2021-2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import common

const
  ServiceName = "fallback_service"

logScope: service = ServiceName

type
  BeaconNodesCounters* = object
    online*: int
    offline*: int
    uninitalized*: int
    incompatible*: int
    nosync*: int

proc onlineNodes*(vc: ValidatorClientRef,
                  roles: set[BeaconNodeRole] = {}): seq[BeaconNodeServerRef] =
  if len(roles) == 0:
    vc.beaconNodes.filterIt(it.status == RestBeaconNodeStatus.Online)
  else:
    vc.beaconNodes.filterIt((it.roles * roles != {}) and
                            (it.status == RestBeaconNodeStatus.Online))

proc onlineNodesCount*(vc: ValidatorClientRef,
                       roles: set[BeaconNodeRole] = {}): int =
  if len(roles) == 0:
    vc.beaconNodes.countIt(it.status == RestBeaconNodeStatus.Online)
  else:
    vc.beaconNodes.countIt((it.roles * roles != {}) and
                           (it.status == RestBeaconNodeStatus.Online))

proc unusableNodes*(vc: ValidatorClientRef): seq[BeaconNodeServerRef] =
  vc.beaconNodes.filterIt(it.status != RestBeaconNodeStatus.Online)

proc unusableNodesCount*(vc: ValidatorClientRef): int =
  vc.beaconNodes.countIt(it.status != RestBeaconNodeStatus.Online)

proc getNodeCounts*(vc: ValidatorClientRef): BeaconNodesCounters =
  var res = BeaconNodesCounters()
  for node in vc.beaconNodes:
    case node.status
    of RestBeaconNodeStatus.Uninitalized:
      inc(res.uninitalized)
    of RestBeaconNodeStatus.Offline:
      inc(res.offline)
    of RestBeaconNodeStatus.Incompatible:
      inc(res.incompatible)
    of RestBeaconNodeStatus.NotSynced:
      inc(res.nosync)
    of RestBeaconNodeStatus.Online:
      inc(res.online)
  res

proc waitOnlineNodes*(vc: ValidatorClientRef, timeoutFut: Future[void] = nil,
                      roles: set[BeaconNodeRole] = {}) {.async.} =
  doAssert(not(isNil(vc.fallbackService)))
  while true:
    if vc.onlineNodesCount(roles) != 0:
      break
    else:
      if vc.fallbackService.onlineEvent.isSet():
        vc.fallbackService.onlineEvent.clear()
        warn "Connection with beacon node(s) has been lost",
              online_nodes = vc.onlineNodesCount(),
              unusable_nodes = vc.unusableNodesCount(),
              total_nodes = len(vc.beaconNodes)
      if isNil(timeoutFut):
        await vc.fallbackService.onlineEvent.wait()
      else:
        let breakLoop =
          block:
            let waitFut = vc.fallbackService.onlineEvent.wait()
            try:
              discard await race(waitFut, timeoutFut)
            except CancelledError as exc:
              if not(waitFut.finished()):
                await waitFut.cancelAndWait()
              raise exc

            if not(waitFut.finished()):
              await waitFut.cancelAndWait()
              true
            else:
              false
        if breakLoop:
          break

proc checkCompatible(vc: ValidatorClientRef,
                     node: BeaconNodeServerRef) {.async.} =
  logScope: endpoint = node
  let info =
    try:
      debug "Requesting beacon node network configuration"
      let res = await node.client.getSpecVC()
      res.data.data
    except CancelledError as exc:
      debug "Configuration request was interrupted"
      node.status = RestBeaconNodeStatus.Offline
      raise exc
    except RestError as exc:
      debug "Unable to obtain beacon node's configuration",
            error_name = exc.name, error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return
    except CatchableError as exc:
      error "Unexpected exception", error_name = exc.name,
            error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return

  let genesis =
    try:
      debug "Requesting beacon node genesis information"
      let res = await node.client.getGenesis()
      res.data.data
    except CancelledError as exc:
      debug "Genesis request was interrupted"
      node.status = RestBeaconNodeStatus.Offline
      raise exc
    except RestError as exc:
      debug "Unable to obtain beacon node's genesis",
            error_name = exc.name, error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return
    except CatchableError as exc:
      error "Unexpected exception", error_name = exc.name,
            error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return

  let genesisFlag = (genesis != vc.beaconGenesis)
  let configFlag =
    # /!\ Keep in sync with `spec/eth2_apis/rest_types.nim` > `RestSpecVC`.
    info.MAX_VALIDATORS_PER_COMMITTEE != MAX_VALIDATORS_PER_COMMITTEE or
    info.SLOTS_PER_EPOCH != SLOTS_PER_EPOCH or
    info.SECONDS_PER_SLOT != SECONDS_PER_SLOT or
    info.EPOCHS_PER_ETH1_VOTING_PERIOD != EPOCHS_PER_ETH1_VOTING_PERIOD or
    info.SLOTS_PER_HISTORICAL_ROOT != SLOTS_PER_HISTORICAL_ROOT or
    info.EPOCHS_PER_HISTORICAL_VECTOR != EPOCHS_PER_HISTORICAL_VECTOR or
    info.EPOCHS_PER_SLASHINGS_VECTOR != EPOCHS_PER_SLASHINGS_VECTOR or
    info.HISTORICAL_ROOTS_LIMIT != HISTORICAL_ROOTS_LIMIT or
    info.VALIDATOR_REGISTRY_LIMIT != VALIDATOR_REGISTRY_LIMIT or
    info.MAX_PROPOSER_SLASHINGS != MAX_PROPOSER_SLASHINGS or
    info.MAX_ATTESTER_SLASHINGS != MAX_ATTESTER_SLASHINGS or
    info.MAX_ATTESTATIONS != MAX_ATTESTATIONS or
    info.MAX_DEPOSITS != MAX_DEPOSITS or
    info.MAX_VOLUNTARY_EXITS != MAX_VOLUNTARY_EXITS or
    info.DOMAIN_BEACON_PROPOSER != DOMAIN_BEACON_PROPOSER or
    info.DOMAIN_BEACON_ATTESTER != DOMAIN_BEACON_ATTESTER or
    info.DOMAIN_RANDAO != DOMAIN_RANDAO or
    info.DOMAIN_DEPOSIT != DOMAIN_DEPOSIT or
    info.DOMAIN_VOLUNTARY_EXIT != DOMAIN_VOLUNTARY_EXIT or
    info.DOMAIN_SELECTION_PROOF != DOMAIN_SELECTION_PROOF or
    info.DOMAIN_AGGREGATE_AND_PROOF != DOMAIN_AGGREGATE_AND_PROOF

  if configFlag or genesisFlag:
    node.status = RestBeaconNodeStatus.Incompatible
    warn "Beacon node has incompatible configuration",
          genesis_flag = genesisFlag, config_flag = configFlag
  else:
    info "Beacon node has compatible configuration"
    node.config = some(info)
    node.genesis = some(genesis)
    node.status = RestBeaconNodeStatus.Online

proc checkSync(vc: ValidatorClientRef,
               node: BeaconNodeServerRef) {.async.} =
  logScope: endpoint = node
  let syncInfo =
    try:
      debug "Requesting beacon node sync status"
      let res = await node.client.getSyncingStatus()
      res.data.data
    except CancelledError as exc:
      debug "Sync status request was interrupted"
      node.status = RestBeaconNodeStatus.Offline
      raise exc
    except RestError as exc:
      debug "Unable to obtain beacon node's sync status",
            error_name = exc.name, error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return
    except CatchableError as exc:
      error "Unexpected exception", error_name = exc.name,
            error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return
  node.syncInfo = some(syncInfo)
  node.status =
    block:
      let optimistic =
        if syncInfo.is_optimistic.isNone():
          "none"
        else:
          $syncInfo.is_optimistic.get()

      if not(syncInfo.is_syncing) or (syncInfo.sync_distance < SYNC_TOLERANCE):
        if not(syncInfo.is_optimistic.get(false)):
          info "Beacon node is in sync", sync_distance = syncInfo.sync_distance,
               head_slot = syncInfo.head_slot, is_opimistic = optimistic
          RestBeaconNodeStatus.Online
        else:
          warn "Beacon node is optimistically synced only",
               sync_distance = syncInfo.sync_distance,
               head_slot = syncInfo.head_slot, is_opimistic = optimistic
          RestBeaconNodeStatus.NotSynced
      else:
        warn "Beacon node not in sync", sync_distance = syncInfo.sync_distance,
             head_slot = syncInfo.head_slot, is_opimistic = optimistic
        RestBeaconNodeStatus.NotSynced

proc checkOnline(node: BeaconNodeServerRef) {.async.} =
  logScope: endpoint = node
  debug "Checking beacon node status"
  let agent =
    try:
      let res = await node.client.getNodeVersion()
      res.data.data
    except CancelledError as exc:
      debug "Status request was interrupted"
      node.status = RestBeaconNodeStatus.Offline
      raise exc
    except RestError as exc:
      debug "Unable to check beacon node's status",
            error_name = exc.name, error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return
    except CatchableError as exc:
      error "Unexpected exception", error_name = exc.name,
            error_message = exc.msg
      node.status = RestBeaconNodeStatus.Offline
      return
  info "Beacon node has been identified", agent = agent.version
  node.ident = some(agent.version)
  node.status = RestBeaconNodeStatus.Online

proc checkNode(vc: ValidatorClientRef,
               node: BeaconNodeServerRef) {.async.} =
  debug "Checking beacon node", endpoint = node
  await node.checkOnline()
  if node.status != RestBeaconNodeStatus.Online:
    return
  await vc.checkCompatible(node)
  if node.status != RestBeaconNodeStatus.Online:
    return
  await vc.checkSync(node)

proc checkNodes*(service: FallbackServiceRef) {.async.} =
  let
    nodesToCheck = service.client.unusableNodes()
    pendingChecks = nodesToCheck.mapIt(service.client.checkNode(it))

  try:
    await allFutures(pendingChecks)
  except CancelledError as exc:
    var pending: seq[Future[void]]
    for future in pendingChecks:
      if not(future.finished()):
        pending.add(future.cancelAndWait())
    await allFutures(pending)
    raise exc

proc mainLoop(service: FallbackServiceRef) {.async.} =
  let vc = service.client
  service.state = ServiceState.Running
  debug "Service started"

  while true:
    # This loop could look much more nicer/better, when
    # https://github.com/nim-lang/Nim/issues/19911 will be fixed, so it could
    # become safe to combine loops, breaks and exception handlers.
    let breakLoop =
      try:
        await service.checkNodes()
        await sleepAsync(2.seconds)
        if service.client.onlineNodesCount() != 0:
          service.onlineEvent.fire()
        else:
          let counter = vc.getNodeCounts()
          warn "No suitable beacon nodes available",
               online_nodes = counter.online,
               offline_nodes = counter.offline,
               uninitalized_nodes = counter.uninitalized,
               incompatible_nodes = counter.incompatible,
               nonsynced_nodes = counter.nosync,
               total_nodes = len(vc.beaconNodes)
        false
      except CancelledError as exc:
        debug "Service interrupted"
        true
      except CatchableError as exc:
        warn "Service crashed with unexpected error", err_name = exc.name,
             err_msg = exc.msg
        true

    if breakLoop:
      break

proc init*(t: typedesc[FallbackServiceRef],
           vc: ValidatorClientRef): Future[FallbackServiceRef] {.async.} =
  logScope: service = ServiceName
  var res = FallbackServiceRef(name: ServiceName, client: vc,
                               state: ServiceState.Initialized,
                               onlineEvent: newAsyncEvent())
  debug "Initializing service"
  # Perform initial nodes check.
  await res.checkNodes()
  return res

proc start*(service: FallbackServiceRef) =
  service.lifeFut = mainLoop(service)
