# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# A port of https://github.com/ethereum/research/blob/master/clock_disparity/ghost_node.py
# Specs: https://ethresear.ch/t/beacon-chain-casper-ffg-rpj-mini-spec/2760
# Part of Casper+Sharding chain v2.1: https://notes.ethereum.org/SCIg8AH5SA-O4C1G1LYZHQ#
# Note that implementation is not updated to the latest v2.1 yet

import
  ./fork_choice_types, ./networksim, ./fork_choice_rule, ./distributions,
  sequtils, times, strformat, tables

let net = newNetworkSimulator(latency = 22)

for i in 0'i32 ..< NOTARIES:
  net.agents.add newNode(
    id = i,
    network = net,
    timestamp = initDuration(seconds = max(normal_distribution(300, 300), 0)) div 10,
    sleepy = i mod 4 == 0
  )

net.generate_peers()
net.run(steps = 100000)

for n in net.agents:
  echo &"Local timestamp: {n.timestamp:>.1}, timequeue len {n.timequeue.len}"
  echo "Main chain head: ", n.blocks[n.main_chain[^1]].height
  echo "Total main chain blocks received: ", toSeq(values(n.blocks)).filterIt(it is Block).len
  # echo "Notarized main chain blocks received: ", toSeq(values(n.blocks)).filterIt((it is Block) and n.is_notarized(it)).len - 1

