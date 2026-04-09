# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, stew/base10, metrics,
  ../spec/network,
  ".."/[beacon_clock],
  ../networking/eth2_network,
  ../consensus_object_pools/blockchain_dag,
  ../rpc/rest_constants

logScope:
  topics = "peer_proto"

type
  StatusMsg* = object
    forkDigest*: ForkDigest
    finalizedRoot*: Eth2Digest
    finalizedEpoch*: Epoch
    headRoot*: Eth2Digest
    headSlot*: Slot

  # https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/fulu/p2p-interface.md#status-v2
  StatusMsgV2* = object
    forkDigest*: ForkDigest
    finalizedRoot*: Eth2Digest
    finalizedEpoch*: Epoch
    headRoot*: Eth2Digest
    headSlot*: Slot
    earliestAvailableSlot*: Slot

  PeerSyncNetworkState* {.final.} = ref object of RootObj
    dag: ChainDAGRef
    cfg: RuntimeConfig
    forkDigests: ref ForkDigests
    genesisBlockRoot: Eth2Digest
    getBeaconTime: GetBeaconTimeFn

  PeerSyncPeerState* {.final.} = ref object of RootObj
    statusLastTime: chronos.Moment
    statusMsg: StatusMsg
    statusMsgV2: Opt[StatusMsgV2]

declareCounter nbc_disconnects_count,
  "Number disconnected peers", labels = ["agent", "reason"]

func shortLog*(s: StatusMsg): auto =
  (
    forkDigest: s.forkDigest,
    finalizedRoot: shortLog(s.finalizedRoot),
    finalizedEpoch: shortLog(s.finalizedEpoch),
    headRoot: shortLog(s.headRoot),
    headSlot: shortLog(s.headSlot)
  )
chronicles.formatIt(StatusMsg): shortLog(it)

func shortLog*(s: StatusMsgV2): auto =
  (
    forkDigest: s.forkDigest,
    finalizedRoot: shortLog(s.finalizedRoot),
    finalizedEpoch: shortLog(s.finalizedEpoch),
    headRoot: shortLog(s.headRoot),
    headSlot: shortLog(s.headSlot),
    earliestAvailableSlot: shortLog(s.earliestAvailableSlot)
  )
chronicles.formatIt(StatusMsgV2): shortLog(it)

func forkDigestAtEpoch(state: PeerSyncNetworkState,
                       epoch: Epoch): ForkDigest =
  state.forkDigests[].atEpoch(epoch, state.cfg)

proc getWallEpoch(state: PeerSyncNetworkState): Epoch =
  state.getBeaconTime().slotOrZero(state.cfg.timeParams).epoch

# https://github.com/ethereum/consensus-specs/blob/v1.5.0-beta.0/specs/phase0/p2p-interface.md#status
proc getCurrentStatusV1(state: PeerSyncNetworkState): StatusMsg =
  let
    dag = state.dag
    wallEpoch = state.getWallEpoch

  if dag != nil:
    StatusMsg(
      forkDigest: state.forkDigestAtEpoch(wallEpoch),
      finalizedRoot:
        (if dag.finalizedHead.slot.epoch != GENESIS_EPOCH:
           dag.finalizedHead.blck.root
         else:
           # this defaults to `Root(b'\x00' * 32)` for the genesis finalized
           # checkpoint
           ZERO_HASH),
      finalizedEpoch: dag.finalizedHead.slot.epoch,
      headRoot: dag.head.root,
      headSlot: dag.head.slot)
  else:
    StatusMsg(
      forkDigest: state.forkDigestAtEpoch(wallEpoch),
      # this defaults to `Root(b'\x00' * 32)` for the genesis finalized
      # checkpoint
      finalizedRoot: ZERO_HASH,
      finalizedEpoch: GENESIS_EPOCH,
      headRoot: state.genesisBlockRoot,
      headSlot: GENESIS_SLOT)

# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.2/specs/fulu/p2p-interface.md#status-v2
proc getCurrentStatusV2(state: PeerSyncNetworkState): StatusMsgV2 =
  let
    dag = state.dag
    wallEpoch = state.getWallEpoch

  if dag != nil:
    StatusMsgV2(
      forkDigest: state.forkDigestAtEpoch(wallEpoch),
      finalizedRoot:
        (if dag.finalizedHead.slot.epoch != GENESIS_EPOCH:
           dag.finalizedHead.blck.root
         else:
           # this defaults to `Root(b'\x00' * 32)` for the genesis finalized
           # checkpoint
           ZERO_HASH),
      finalizedEpoch: dag.finalizedHead.slot.epoch,
      headRoot: dag.head.root,
      headSlot: dag.head.slot,
      earliestAvailableSlot: dag.earliestAvailableSlot())
  else:
    StatusMsgV2(
      forkDigest: state.forkDigestAtEpoch(wallEpoch),
      # this defaults to `Root(b'\x00' * 32)` for the genesis finalized
      # checkpoint
      finalizedRoot: ZERO_HASH,
      finalizedEpoch: GENESIS_EPOCH,
      headRoot: state.genesisBlockRoot,
      headSlot: GENESIS_SLOT,
      earliestAvailableSlot: GENESIS_SLOT)

proc checkStatusMsg(state: PeerSyncNetworkState, status: StatusMsg | StatusMsgV2):
    Result[void, cstring] =
  let
    dag = state.dag
    wallSlot = (
      state.getBeaconTime() + MAXIMUM_GOSSIP_CLOCK_DISPARITY
    ).slotOrZero(state.cfg.timeParams)

  if status.finalizedEpoch > status.headSlot.epoch:
    # Can be equal during genesis or checkpoint start
    return err("finalized epoch newer than head")

  if status.headSlot > wallSlot:
    return err("head more recent than wall clock")

  if state.forkDigestAtEpoch(wallSlot.epoch) != status.forkDigest:
    return err("fork digests differ")

  # https://github.com/ethereum/consensus-specs/blob/v1.4.0/specs/phase0/p2p-interface.md#status
  if dag != nil:
    if status.finalizedEpoch <= dag.finalizedHead.slot.epoch:
      let blockId = dag.getBlockIdAtSlot(status.finalizedEpoch.start_slot())
      if blockId.isSome and
          (not status.finalizedRoot.isZero) and
          status.finalizedRoot != blockId.get().bid.root:
        return err("peer following different finality")
  else:
    if status.finalizedEpoch == GENESIS_EPOCH:
      # "this defaults to `Root(b'\x00' * 32)` for the genesis finalized checkpoint"
      # keep compatibility with Lighthouse and other Nimbus for a while, which
      # apparently don't use spec ZERO_HASH as of this writing
      if not (status.finalizedRoot in [state.genesisBlockRoot, ZERO_HASH]):
        return err("peer following different finality")
  ok()

proc handleStatusV1(peer: Peer,
                    state: PeerSyncNetworkState,
                    theirStatus: StatusMsg): Future[bool] {.async: (raises: [CancelledError]).}

proc handleStatusV2(peer: Peer,
                    state: PeerSyncNetworkState,
                    theirStatus: StatusMsgV2): Future[bool] {.async: (raises: [CancelledError]).}

proc setStatusV2Msg(state: PeerSyncPeerState,
                    statusMsg: Opt[StatusMsgV2]) =
  state.statusMsgV2 = statusMsg
  state.statusLastTime = Moment.now()

{.pop.} # TODO fix p2p macro for raises

p2pProtocol PeerSync(version = 1,
                       networkState = PeerSyncNetworkState,
                       peerState = PeerSyncPeerState):

  onPeerConnected do (peer: Peer, incoming: bool) {.
    async: (raises: [CancelledError]).}:
    debug "Peer connected", peer, peerId = shortLog(peer.peerId), incoming
    # Per the eth2 protocol, whoever dials must send a status message when
    # connected for the first time, but because of how libp2p works, there may
    # be a race between incoming and outgoing connections and disconnects that
    # makes the incoming flag unreliable / obsolete by the time we get to
    # this point - instead of making assumptions, we'll just send a status
    # message redundantly.
    # TODO(zah)
    #      the spec does not prohibit sending the extra status message on
    #      incoming connections, but it should not be necessary - this would
    #      need a dedicated flow in libp2p that resolves the race conditions -
    #      this needs more thinking around the ordering of events and the
    #      given incoming flag

    let wallEpoch = peer.networkState.getWallEpoch
    if wallEpoch >= peer.networkState.cfg.FULU_FORK_EPOCH:
      let
        ourStatus = peer.networkState.getCurrentStatusV2()
        theirStatus =
          await peer.statusV2(ourStatus, timeout = RESP_TIMEOUT_DUR)

      if theirStatus.isOk:
        discard await peer.handleStatusV2(peer.networkState, theirStatus.get())
        peer.updateAgent()
      else:
        # Mark status v2 of remote peer as None.
        peer.state(PeerSync).setStatusV2Msg(Opt.none(StatusMsgV2))
        debug "Status response not received in time",
              peer, errorKind = theirStatus.error.kind
        await peer.disconnect(FaultOrError)

    else:
      let
        ourStatus = peer.networkState.getCurrentStatusV1()
        theirStatus =
          await peer.statusV1(ourStatus, timeout = RESP_TIMEOUT_DUR)

      if theirStatus.isOk:
        discard await peer.handleStatusV1(peer.networkState, theirStatus.get())
        peer.updateAgent()
      else:
        debug "Status response not received in time",
              peer, errorKind = theirStatus.error.kind
        await peer.disconnect(FaultOrError)

  proc statusV1(peer: Peer,
                theirStatus: StatusMsg,
                response: SingleChunkResponse[StatusMsg])
      {.async, libp2pProtocol("status", 1).} =
    let ourStatus = peer.networkState.getCurrentStatusV1()
    trace "Sending status (v1)", peer = peer, status = ourStatus
    await response.send(ourStatus)
    discard await peer.handleStatusV1(peer.networkState, theirStatus)

  proc statusV2(peer: Peer,
                theirStatus: StatusMsgV2,
                response: SingleChunkResponse[StatusMsgV2])
      {.async, libp2pProtocol("status", 2).} =
    let ourStatus = peer.networkState.getCurrentStatusV2()
    trace "Sending status (v2)", peer = peer, status = ourStatus
    await response.send(ourStatus)
    discard await peer.handleStatusV2(peer.networkState, theirStatus)

  proc ping(peer: Peer, value: uint64): uint64
    {.libp2pProtocol("ping", 1).} =
    peer.network.metadata.seq_number

  proc getMetadata_v2(peer: Peer): altair.MetaData
    {.libp2pProtocol("metadata", 2).} =
    let altair_metadata = altair.MetaData(
      seq_number: peer.network.metadata.seq_number,
      attnets: peer.network.metadata.attnets,
      syncnets: peer.network.metadata.syncnets)
    altair_metadata

  proc getMetadata_v3(peer: Peer): fulu.MetaData
    {.libp2pProtocol("metadata", 3).} =
    peer.network.metadata

  proc goodbye(peer: Peer, reason: uint64) {.
       async, libp2pProtocol("goodbye", 1).} =
    let remoteAgent = peer.getRemoteAgent()
    nbc_disconnects_count.inc(1, [$remoteAgent, Base10.toString(reason)])
    debug "Received Goodbye message",
          reason = disconnectReasonName(remoteAgent, reason),
          remote_agent = $remoteAgent, peer

proc setStatusMsg(peer: Peer, statusMsg: StatusMsg) =
  debug "Peer status", peer, statusMsg
  peer.state(PeerSync).statusMsg = statusMsg
  peer.state(PeerSync).statusLastTime = Moment.now()

proc setStatusV2Msg(peer: Peer, statusMsg: Opt[StatusMsgV2]) =
  debug "Peer statusV2", peer, statusMsg
  peer.state(PeerSync).statusMsgV2 = statusMsg
  peer.state(PeerSync).statusLastTime = Moment.now()

proc handleStatusV1(peer: Peer,
                    state: PeerSyncNetworkState,
                    theirStatus: StatusMsg): Future[bool]
                    {.async: (raises: [CancelledError]).} =
  let
    res = checkStatusMsg(state, theirStatus)

  return if res.isErr():
    debug "Irrelevant peer", peer, theirStatus, err = res.error()
    await peer.disconnect(IrrelevantNetwork)
    false
  else:
    peer.setStatusMsg(theirStatus)

    if peer.connectionState == Connecting:
      # As soon as we get here it means that we passed handshake succesfully. So
      # we can add this peer to PeerPool.
      await peer.handlePeer()
    true

proc handleStatusV2(peer: Peer,
                    state: PeerSyncNetworkState,
                    theirStatus: StatusMsgV2): Future[bool]
                    {.async: (raises: [CancelledError]).} =
  let
    res = checkStatusMsg(state, theirStatus)

  return if res.isErr():
    debug "Irrelevant peer", peer, theirStatus, err = res.error()
    await peer.disconnect(IrrelevantNetwork)
    false
  else:
    peer.setStatusV2Msg(Opt.some(theirStatus))

    if peer.connectionState == Connecting:
      # As soon as we get here it means that we passed handshake succesfully. So
      # we can add this peer to PeerPool.
      await peer.handlePeer()
    true

proc updateStatus*(peer: Peer): Future[bool] {.async: (raises: [CancelledError]).} =
  ## Request `status` of remote peer ``peer``.
  let nstate = peer.networkState(PeerSync)
  if nstate.getWallEpoch >= nstate.cfg.FULU_FORK_EPOCH:
    let
      ourStatus = getCurrentStatusV2(nstate)
      theirStatus =
        (await peer.statusV2(ourStatus, timeout = RESP_TIMEOUT_DUR))
    if theirStatus.isOk():
      await peer.handleStatusV2(nstate, theirStatus.get())
    else:
      # Mark status v2 of remote peer as None
      peer.setStatusV2Msg(Opt.none(StatusMsgV2))
      return false

  else:
    let
      ourStatus = getCurrentStatusV1(nstate)
      theirStatus =
        (await peer.statusV1(ourStatus, timeout = RESP_TIMEOUT_DUR)).valueOr:
          return false

    await peer.handleStatusV1(nstate, theirStatus)

proc getHeadRoot*(peer: Peer): Eth2Digest =
  let
    state = peer.networkState(PeerSync)
    pstate = peer.state(PeerSync)
  if pstate.statusMsgV2.isSome():
    pstate.statusMsgV2.get.headRoot
  else:
    pstate.statusMsg.headRoot

proc getHeadSlot*(peer: Peer): Slot =
  let
    state = peer.networkState(PeerSync)
    pstate = peer.state(PeerSync)
  if pstate.statusMsgV2.isSome():
    pstate.statusMsgV2.get.headSlot
  else:
    pstate.statusMsg.headSlot

proc getFinalizedEpoch*(peer: Peer): Epoch =
  let
    state = peer.networkState(PeerSync)
    pstate = peer.state(PeerSync)
  if pstate.statusMsgV2.isSome():
    pstate.statusMsgV2.get.finalizedEpoch
  else:
    pstate.statusMsg.finalizedEpoch

proc getFinalizedRoot*(peer: Peer): Eth2Digest =
  ## Returns finalized checkpoint's root for specific peer ``peer``.
  let pstate = peer.state(PeerSync)
  if pstate.statusMsgV2.isSome():
    pstate.statusMsgV2.get.finalizedRoot
  else:
    pstate.statusMsg.finalizedRoot

proc getForkDigest*(peer: Peer): ForkDigest =
  ## Returns fork for specific peer ``peer``.
  let pstate = peer.state(PeerSync)
  if pstate.statusMsgV2.isSome():
    pstate.statusMsgV2.get.forkDigest
  else:
    pstate.statusMsg.forkDigest

proc getFinalizedCheckpoint*(peer: Peer): Checkpoint =
  ## Returns finalized checkpoint's root for specific peer ``peer``.
  let pstate = peer.state(PeerSync)
  if pstate.statusMsgV2.isSome():
    Checkpoint(
      root: pstate.statusMsgV2.get.finalizedRoot,
      epoch: pstate.statusMsgV2.get.finalizedEpoch)
  else:
    Checkpoint(
      root: pstate.statusMsg.finalizedRoot,
      epoch: pstate.statusMsg.finalizedEpoch)

proc getHeadBlockId*(peer: Peer): BlockId =
  ## Returns head BlockId for specific peer ``peer``.
  let pstate = peer.state(PeerSync)
  if pstate.statusMsgV2.isSome():
    BlockId(
      root: pstate.statusMsgV2.get.headRoot,
      slot: pstate.statusMsgV2.get.headSlot)
  else:
    BlockId(
      root: pstate.statusMsg.headRoot,
      slot: pstate.statusMsg.headSlot)

proc getEarliestAvailableSlot*(peer: Peer): Opt[Slot] =
  ## Returns earliest available slot for specific peer ``peer``.
  let
    pstate = peer.state(PeerSync)
    msg = pstate.statusMsgV2.valueOr:
      return Opt.none(Slot)
  Opt.some(msg.earliestAvailableSlot)

proc getStatusLastTime*(peer: Peer): chronos.Moment =
  ## Returns head slot for specific peer ``peer``.
  peer.state(PeerSync).statusLastTime

proc init*(T: type PeerSync.NetworkState,
    dag: ChainDAGRef, getBeaconTime: GetBeaconTimeFn): T =
  T(
    dag: dag,
    cfg: dag.cfg,
    forkDigests: dag.forkDigests,
    genesisBlockRoot: dag.genesisBlockRoot,
    getBeaconTime: getBeaconTime,
  )

func init*(T: type PeerSync.NetworkState,
                     cfg: RuntimeConfig,
                     forkDigests: ref ForkDigests,
                     genesisBlockRoot: Eth2Digest,
                     getBeaconTime: GetBeaconTimeFn): T =
  T(
    dag: nil,
    cfg: cfg,
    forkDigests: forkDigests,
    genesisBlockRoot: genesisBlockRoot,
    getBeaconTime: getBeaconTime,
  )
