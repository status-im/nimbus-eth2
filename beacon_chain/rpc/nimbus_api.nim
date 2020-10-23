# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/strutils,
  stew/shims/macros,
  stew/byteutils,
  json_rpc/[rpcserver, jsonmarshal],

  ../beacon_node_common, ../eth2_network,
  ../spec/[digest, datatypes, presets]

logScope: topics = "nimbusapi"

type
  RpcServer = RpcHttpServer

proc installNimbusApiHandlers*(rpcServer: RpcServer, node: BeaconNode) =
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
    let
      wallSlot = currentSlot(node)
      headSlot = node.chainDag.head.slot
    # FIXME: temporary hack: If more than 1 block away from expected head, then we are "syncing"
    return (headSlot + 1) < wallSlot

  rpcServer.rpc("getNetworkPeerId") do () -> string:
    return $publicKey(node.network)

  rpcServer.rpc("getNetworkPeers") do () -> seq[string]:
    for peerId, peer in node.network.peerPool:
      result.add $peerId

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
