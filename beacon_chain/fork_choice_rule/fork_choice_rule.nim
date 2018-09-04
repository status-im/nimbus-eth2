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
  tables, deques, strutils,  # Stdlib
  nimcrypto,                 # Nimble packages
  # ../datatypes, # BeaconBlock is still different from the simulation blocks
  # Local imports
  ./fork_choice_types,
  ./networksim

###########################################################
# Forward declarations

method on_receive(self: Node, obj: BlockOrSig, reprocess = false) {.base.} =
  raise newException(ValueError, "Not implemented error. Please implement in child types")

###########################################################

proc broadcast(self: Node, x: Block) =
  if self.sleepy and self.timestamp != 0:
    return
  self.network.broadcast(self, x)
  self.on_receive(x)

proc log(self: Node, words: string, lvl = 3, all = false) =
  if (self.id == 0 or all) and lvl >= 2:
    echo self.id, words

func add_to_timequeue(self: Node, obj: Block) =
  var i = 0
  while i < self.timequeue.len and self.timequeue[i].min_timestamp < obj.min_timestamp:
    inc i
  self.timequeue.insert(obj, i)

func add_to_multiset[K, V](
    self: Node,
    multiset: TableRef[K, seq[V]],
    k: K,
    v: V or seq[V]) =
  if k notin multiset:
    multiset[k] = @[]
  multiset[k].add v

func change_head(self: Node, chain: var seq[MDigest[256]], new_head: Block) =
  chain.add newSeq[MDigest[256]](new_head.height + 1 - chain.len)
  var (i, c) = (new_head.height, new_head.hash)
  while c != chain[i]:
    chain[i] = c
    c = self.blocks[c].parent_hash
    dec i
  for idx, val in chain:
    doAssert self.blocks[val].height == idx

func recalculate_head(self: Node) =
  while true:
    var
      descendant_queue = initDeque[MDigest[256]]()
      new_head: MDigest[256]
      max_count = 0
    descendant_queue.addFirst self.main_chain[^1]
    while descendant_queue.len != 0:
      let first = descendant_queue.popFirst()
      if first in self.children:
        for c in self.children[first]:
          descendant_queue.addLast c
      if self.scores.getOrDefault(first, 0) > max_count and first != self.main_chain[^1]:
        new_head = first
        max_count = self.scores.getOrDefault(first, 0)
    if new_head != MDigest[256](): # != default init, a 32-byte array of 0
      self.change_head(self.main_chain, self.blocks[new_head])
    else:
      return

proc process_children(self: Node, h: MDigest[256]) =
  if h in self.parentqueue:
    for b in self.parentqueue[h]:
      self.on_receive(b, reprocess = true)
    self.parentqueue.del h

func get_common_ancestor(self: Node, hash_a, hash_b: MDigest[256]): Block =
  var (a, b) = (self.blocks[hash_a], self.blocks[hash_b])
  while b.height > a.height:
    b = self.blocks[b.parent_hash]
  while a.height > b.height:
    a = self.blocks[a.parent_hash]
  while a.hash != b.hash:
    a = self.blocks[a.parent_hash]
    b = self.blocks[b.parent_hash]
  return a

func is_descendant(self: Node, hash_a, hash_b: MDigest[256]): bool =
  let a = self.blocks[hash_a]
  var b = self.blocks[hash_b]
  while b.height > a.height:
    b = self.blocks[b.parent_hash]
  return a.hash == b.hash

proc have_ancestry(self: Node, h: MDigest[256]): bool =
  let h = BlockHash(raw: h)
  while h.raw != Genesis.hash:
    if h notin self.processed:
      return false
    let wip = self.processed[h]
    if wip is Block:
      h.raw = Block(wip).parent_hash
  return true

proc on_receive(self: Node, blck: Block, reprocess = false) =
  block: # Common part of on_receive
    let hash = BlockHash(raw: blck.hash)
    if hash in self.processed and not reprocess:
      return
    self.processed[hash] = blck

  # parent not yet received
  if blck.parent_hash notin self.blocks:
    self.add_to_multiset(self.parentqueue, blck.parent_hash, blck)
    return
  # Too early
  if blck.min_timestamp > self.timestamp:
    self.add_to_timequeue(blck)
    return
  # Add the block
  self.log("Processing beacon block &" % blck.hash.data[0 .. ^4].toHex(false))
  self.blocks[blck.hash] = blck
  # Is the block building on the head? Then add it to the head!
  if blck.parent_hash == self.main_chain[^1] or self.careless:
    self.main_chain.add(blck.hash)
  # Add child record
  self.add_to_multiset(self.children, blck.parent_hash, blck.hash)
  # Final steps
  self.process_children(blck.hash)
  self.network.broadcast(self, blck)

proc on_receive(self: Node, sig: Sig, reprocess = false) =
  block: # Common part of on_receive
    let hash = SigHash(raw: sig.hash)
    if hash in self.processed and not reprocess:
      return
    self.processed[hash] = sig

  if sig.targets[0] notin self.blocks:
    self.add_to_multiset(self.parentqueue, sig.targets[0], sig)
    return

  # Get common ancestor

