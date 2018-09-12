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
  ./fork_choice_types, ./fork_choice_rule, ./distributions

proc newNetworkSimulator*(latency: int): NetworkSimulator =
  new result
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
    self.peers.mgetOrPut(a.id, @[]).add p
    for peer in p:
      self.peers.mgetOrPut(peer.id, @[]).add a

proc tick*(self: NetworkSimulator) =
  if self.time in self.objqueue:
    # on_receive, calls broadcast which will enqueue new BlockOrSig in objqueue
    # so we can't for loop like in EF research repo (modifying length is not allowed)
    var ros: seq[tuple[recipient: Node, obj: BlockOrSig]]
    shallowCopy(ros, self.objqueue[self.time])
    var i = 0
    while i < ros.len:
      let (recipient, obj) = ros[i]
      if rand(1.0) < self.reliability:
        recipient.on_receive(obj)
      inc i
    self.objqueue.del self.time
  for a in self.agents:
    a.tick()
  self.time += initDuration(seconds = 1)

proc run*(self: NetworkSimulator, steps: int) =
  for i in 0 ..< steps:
    self.tick()

# func broadcast*(self: NetworkSimulator, sender: Node, obj: BlockOrSig)
#   ## defined in fork_choice_types.nim

proc direct_send(self: NetworkSimulator, to_id: int32, obj: BlockOrSig) =
  for a in self.agents:
    if a.id == to_id:
      let recv_time = self.time + self.latency_distribution_sample()
      # if recv_time notin self.objqueue: # Unneeded with seq "not nil" changes
      #   self.objqueue[recv_time] = @[]
      self.objqueue[recv_time].add (a, obj)

proc knock_offline_random(self: NetworkSimulator, n: int) =
  var ko = initTable[int32, Node]()
  while ko.len < n:
    let c = rand(self.agents)
    ko[c.id] = c
  # for c in ko.values: # Unneeded with seq "not nil" changes
  #   self.peers[c.id] = @[]
  for a in self.agents:
    self.peers[a.id] = lc[x | (x <- self.peers[a.id], x.id notin ko), Node] # List comprehension

proc partition(self: NetworkSimulator) =
  var a = initTable[int32, Node]()
  while a.len < self.agents.len div 2:
    let c = rand(self.agents)
    a[c.id] = c
  for c in self.agents:
    if c.id in a:
      self.peers[c.id] = lc[x | (x <- self.peers[c.id], x.id in a), Node]
    else:
      self.peers[c.id] = lc[x | (x <- self.peers[c.id], x.id notin a), Node]

