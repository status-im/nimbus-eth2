# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/strutils,
  chronos,
  stew/shims/macros,
  stew/byteutils,
  json_rpc/[rpcserver, jsonmarshal],

  ../beacon_node_common, ../nimbus_binary_common, ../eth2_network,
  ../spec/[digest, datatypes, presets]

logScope: topics = "nimbusapi"

type
  RpcServer = RpcHttpServer

when defined(chronosFutureTracking):
  type
    FutureInfo* = object
      id*: int
      procname*: string
      filename*: string
      line*: int
      state: string

proc installNimbusApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
  ## Install non-standard api handlers - some of these are used by 3rd-parties
  ## such as eth2stats, pending a full REST api
  rpcServer.rpc("getBeaconHead") do () -> Slot:
    return node.chainDag.head.slot

  rpcServer.rpc("getChainHead") do () -> JsonNode:
    let
      head = node.chainDag.head
      finalized = node.chainDag.headState.data.data.finalized_checkpoint
      justified = node.chainDag.headState.data.data.current_justified_checkpoint
    return %* {
      "head_slot": head.slot,
      "head_block_root": head.root.data.toHex(),
      "finalized_slot": finalized.epoch * SLOTS_PER_EPOCH,
      "finalized_block_root": finalized.root.data.toHex(),
      "justified_slot": justified.epoch * SLOTS_PER_EPOCH,
      "justified_block_root": justified.root.data.toHex(),
    }

  rpcServer.rpc("getSyncing") do () -> bool:
    return node.syncManager.inProgress

  rpcServer.rpc("getNetworkPeerId") do () -> string:
    return $node.network.peerId()

  rpcServer.rpc("getNetworkPeers") do () -> seq[string]:
    for peerId, peer in node.network.peerPool:
      result.add $peerId

  rpcServer.rpc("getNodeVersion") do () -> string:
    return "Nimbus/" & fullVersionStr

  rpcServer.rpc("getSpecPreset") do () -> JsonNode:
    var res = newJObject()
    genStmtList:
      for presetValue in PresetValue:
        if presetValue notin ignoredValues + runtimeValues:
          let
            settingSym = ident($presetValue)
            settingKey = newLit(toLowerAscii($presetValue))
          let f = quote do:
            res[`settingKey`] = %(presets.`settingSym`)
          yield f

    for field, value in fieldPairs(node.config.runtimePreset):
      res[field] = when value isnot Version: %value
                   else: %value.toUInt64

    return res

  rpcServer.rpc("peers") do () -> JsonNode:
    var res = newJObject()
    var peers = newJArray()
    for id, peer in node.network.peerPool:
      peers.add(
        %(
          info: shortLog(peer.info),
          connectionState: $peer.connectionState,
          score: peer.score,
        )
      )
    res.add("peers", peers)

    return res

  rpcServer.rpc("setLogLevel") do (level: string) -> bool:
    {.gcsafe.}: # It's probably not, actually. Hopefully we don't log from threads...
      updateLogLevel(level)
    return true

  when defined(chronosFutureTracking):
    rpcServer.rpc("getChronosFutures") do () -> seq[FutureInfo]:
      var res: seq[FutureInfo]

      for item in pendingFutures():
        let loc = item.location[LocCreateIndex][]
        res.add FutureInfo(
          id: item.id,
          procname: $loc.procedure,
          filename: $loc.file,
          line: loc.line,
          state: $item.state
        )

      return res
