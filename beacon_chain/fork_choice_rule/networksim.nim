# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# A port of https://github.com/ethereum/research/blob/master/clock_disparity/ghost_node.py
# Specs: https://ethresear.ch/t/beacon-chain-casper-ffg-rpj-mini-spec/2760
# Part of Casper+Sharding chain v2.1: https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ#

import
  tables, times, sugar, random,
  ./fork_choice_types, ./distributions

proc initNetworkSimulator*(latency: int): NetworkSimulator =
  result.latency_distribution_sample = () => initDuration(
    seconds = max(
      0,
      normal_distribution(latency, latency * 2 div 5)
    )
  )
  result.reliability = 0.9
  result.objqueue = newTable[Duration, seq[(Node, BlockOrSig)]]()
  result.peers = newTable[int, seq[Node]]()

proc generate_peers*(self: NetworkSimulator, num_peers = 5) =
  self.peers.clear()
  var p: seq[Node]
  for a in self.agents:
    p.setLen(0) # reset without involving GC/realloc
    while p.len <= num_peers div 2:
      p.add self.agents.rand()
      if p[^1] == a:
        discard p.pop()
    self.peers[a.id].add p
    for peer in p:
      self.peers[peer.id].add a

func broadcast*(self: NetworkSimulator, sender: Node, obj: BlockOrSig) =
  for p in self.peers[sender.id]:
    let recv_time = self.time + self.latency_distribution_sample()
    if recv_time notin self.objqueue:
      self.objqueue[recv_time] = @[]
    self.objqueue[recv_time].add (p, obj)
