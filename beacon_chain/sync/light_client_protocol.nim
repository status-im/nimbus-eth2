# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, chronos, snappy, snappy/codec,
  ../spec/[helpers, forks, network],
  ../networking/eth2_network,
  ../consensus_object_pools/blockchain_dag,
  ../rpc/rest_constants

logScope:
  topics = "lc_proto"

const
  lightClientBootstrapResponseCost = allowedOpsPerSecondCost(1)
    ## Only one bootstrap per peer should ever be needed - no need to allow more
  lightClientUpdateResponseCost = allowedOpsPerSecondCost(1000)
    ## Updates are tiny - we can allow lots of them
  lightClientFinalityUpdateResponseCost = allowedOpsPerSecondCost(100)
  lightClientOptimisticUpdateResponseCost = allowedOpsPerSecondCost(100)

type
  LightClientNetworkState* {.final.} = ref object of RootObj
    dag*: ChainDAGRef

proc readChunkPayload*(
    conn: Connection, peer: Peer, MsgType: type SomeForkedLightClientObject):
    Future[NetRes[MsgType]] {.async: (raises: [CancelledError]).} =
  var contextBytes: ForkDigest
  try:
    await conn.readExactly(addr contextBytes, sizeof contextBytes)
  except CatchableError:
    return neterr UnexpectedEOF
  let contextFork =
    peer.network.forkDigests[].consensusForkForDigest(contextBytes).valueOr:
      return neterr InvalidContextBytes

  withLcDataFork(lcDataForkAtConsensusFork(contextFork)):
    when lcDataFork > LightClientDataFork.None:
      let res = await eth2_network.readChunkPayload(
        conn, peer, MsgType.Forky(lcDataFork))
      if res.isOk:
        if contextFork !=
            peer.network.cfg.consensusForkAtEpoch(res.get.contextEpoch):
          return neterr InvalidContextBytes
        return ok MsgType.init(res.get)
      else:
        return err(res.error)
    else:
      return neterr InvalidContextBytes

{.pop.}

func forkDigestAtEpoch(state: LightClientNetworkState,
                       epoch: Epoch): ForkDigest =
  state.dag.forkDigests[].atEpoch(epoch, state.dag.cfg)

p2pProtocol LightClientSync(version = 1,
                       networkState = LightClientNetworkState):
  # https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/specs/altair/light-client/p2p-interface.md#getlightclientbootstrap
  proc lightClientBootstrap(
      peer: Peer,
      blockRoot: Eth2Digest,
      response: SingleChunkResponse[ForkedLightClientBootstrap])
      {.async, libp2pProtocol("light_client_bootstrap", 1).} =
    trace "Received LC bootstrap request", peer, blockRoot
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let bootstrap = dag.getLightClientBootstrap(blockRoot)
    withForkyBootstrap(bootstrap):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyBootstrap.contextEpoch
          contextBytes = peer.networkState.forkDigestAtEpoch(contextEpoch).data

        # TODO extract from libp2pProtocol
        peer.awaitQuota(
          lightClientBootstrapResponseCost,
          "light_client_bootstrap/1")
        await response.sendSSZ(forkyBootstrap, contextBytes)
      else:
        raise newException(ResourceUnavailableError, LCBootstrapUnavailable)

    debug "LC bootstrap request done", peer, blockRoot

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/altair/light-client/p2p-interface.md#lightclientupdatesbyrange
  proc lightClientUpdatesByRange(
      peer: Peer,
      startPeriod: SyncCommitteePeriod,
      reqCount: uint64,
      response: MultipleChunksResponse[
        ForkedLightClientUpdate, MAX_REQUEST_LIGHT_CLIENT_UPDATES])
      {.async, libp2pProtocol("light_client_updates_by_range", 1).} =
    trace "Received LC updates by range request", peer, startPeriod, reqCount
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let
      headPeriod = dag.head.slot.sync_committee_period
      # Limit number of updates in response
      maxSupportedCount =
        if startPeriod > headPeriod:
          0'u64
        else:
          min(headPeriod + 1 - startPeriod, MAX_REQUEST_LIGHT_CLIENT_UPDATES)
      count = min(reqCount, maxSupportedCount)
      onePastPeriod = startPeriod + count

    var found = 0
    for period in startPeriod..<onePastPeriod:
      let update = dag.getLightClientUpdateForPeriod(period)
      withForkyUpdate(update):
        when lcDataFork > LightClientDataFork.None:
          let
            contextEpoch = forkyUpdate.contextEpoch
            contextBytes =
              peer.networkState.forkDigestAtEpoch(contextEpoch).data

          # TODO extract from libp2pProtocol
          peer.awaitQuota(
            lightClientUpdateResponseCost,
            "light_client_updates_by_range/1")
          await response.writeSSZ(forkyUpdate, contextBytes)
          inc found
        else:
          discard

    debug "LC updates by range request done", peer, startPeriod, count, found

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/altair/light-client/p2p-interface.md#getlightclientfinalityupdate
  proc lightClientFinalityUpdate(
      peer: Peer,
      response: SingleChunkResponse[ForkedLightClientFinalityUpdate])
      {.async, libp2pProtocol("light_client_finality_update", 1).} =
    trace "Received LC finality update request", peer
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let finality_update = dag.getLightClientFinalityUpdate()
    withForkyFinalityUpdate(finality_update):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyFinalityUpdate.contextEpoch
          contextBytes = peer.networkState.forkDigestAtEpoch(contextEpoch).data

        # TODO extract from libp2pProtocol
        peer.awaitQuota(
          lightClientFinalityUpdateResponseCost,
          "light_client_finality_update/1")
        await response.sendSSZ(forkyFinalityUpdate, contextBytes)
      else:
        raise newException(ResourceUnavailableError, LCFinUpdateUnavailable)

    debug "LC finality update request done", peer

  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/altair/light-client/p2p-interface.md#getlightclientoptimisticupdate
  proc lightClientOptimisticUpdate(
      peer: Peer,
      response: SingleChunkResponse[ForkedLightClientOptimisticUpdate])
      {.async, libp2pProtocol("light_client_optimistic_update", 1).} =
    trace "Received LC optimistic update request", peer
    let dag = peer.networkState.dag
    doAssert dag.lcDataStore.serve

    let optimistic_update = dag.getLightClientOptimisticUpdate()
    withForkyOptimisticUpdate(optimistic_update):
      when lcDataFork > LightClientDataFork.None:
        let
          contextEpoch = forkyOptimisticUpdate.contextEpoch
          contextBytes = peer.networkState.forkDigestAtEpoch(contextEpoch).data

        # TODO extract from libp2pProtocol
        peer.awaitQuota(
          lightClientOptimisticUpdateResponseCost,
          "light_client_optimistic_update/1")
        await response.sendSSZ(forkyOptimisticUpdate, contextBytes)
      else:
        raise newException(ResourceUnavailableError, LCOptUpdateUnavailable)

    debug "LC optimistic update request done", peer

proc init*(T: type LightClientSync.NetworkState, dag: ChainDAGRef): T =
  T(
    dag: dag,
  )
