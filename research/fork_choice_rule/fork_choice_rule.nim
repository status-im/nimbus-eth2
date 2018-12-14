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
  # Stdlib
  tables, deques, strutils, endians, strformat,
  times, sequtils,
  # Nimble packages
  nimcrypto,
  # Local imports
  ./fork_choice_types

proc broadcast(self: Node, x: BlockOrSig) =
  if self.sleepy and self.timestamp != DurationZero:
    return
  self.network.broadcast(self, x)
  self.on_receive(x)

proc log(self: Node, words: string, lvl = 3, all = false) =
  if (self.id == 0 or all) and lvl >= 2:
    echo self.id, " - ", words

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
  multiset.mgetOrPut(k, @[]).add v

func change_head(self: Node, chain: var seq[Eth2Digest], new_head: Block) =
  chain.add newSeq[Eth2Digest](new_head.height + 1 - chain.len)
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
      descendant_queue = initDeque[Eth2Digest]()
      new_head: Eth2Digest
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
    if new_head != Eth2Digest(): # != default init, a 32-byte array of 0
      self.change_head(self.main_chain, self.blocks[new_head])
    else:
      return

proc process_children(self: Node, h: Eth2Digest) =
  if h in self.parentqueue:
    for b in self.parentqueue[h]:
      self.on_receive(b, reprocess = true)
    self.parentqueue.del h

func get_common_ancestor(self: Node, hash_a, hash_b: Eth2Digest): Block =
  var (a, b) = (self.blocks[hash_a], self.blocks[hash_b])
  while b.height > a.height:
    b = self.blocks[b.parent_hash]
  while a.height > b.height:
    a = self.blocks[a.parent_hash]
  while a.hash != b.hash:
    a = self.blocks[a.parent_hash]
    b = self.blocks[b.parent_hash]
  return a

func is_descendant(self: Node, hash_a, hash_b: Eth2Digest): bool =
  let a = self.blocks[hash_a]
  var b = self.blocks[hash_b]
  while b.height > a.height:
    b = self.blocks[b.parent_hash]
  return a.hash == b.hash

proc have_ancestry(self: Node, h: Eth2Digest): bool =
  let h = BlockHash(raw: h)
  while h.raw != Genesis.hash:
    if h notin self.processed:
      return false
    let wip = self.processed[h]
    if wip is Block:
      h.raw = Block(wip).parent_hash
  return true

method on_receive(self: Node, blck: Block, reprocess = false) =
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
  self.log "Processing beacon block " & blck.hash.data[0 .. ^4].toHex(false)
  self.blocks[blck.hash] = blck
  # Is the block building on the head? Then add it to the head!
  if blck.parent_hash == self.main_chain[^1] or self.careless:
    self.main_chain.add(blck.hash)
  # Add child record
  self.add_to_multiset(self.children, blck.parent_hash, blck.hash)
  # Final steps
  self.process_children(blck.hash)
  self.network.broadcast(self, blck)

method on_receive(self: Node, sig: Sig, reprocess = false) =
  block: # Common part of on_receive
    let hash = SigHash(raw: sig.hash)
    if hash in self.processed and not reprocess:
      return
    self.processed[hash] = sig

  if sig.targets[0] notin self.blocks:
    self.add_to_multiset(self.parentqueue, sig.targets[0], sig)
    return
  # Get common ancestor
  let anc = self.get_common_ancestor(self.main_chain[^1], sig.targets[0])
  let max_score = block:
    var max = 0
    for i in anc.height + 1 ..< self.main_chain.len:
      max = max(max, self.scores.getOrDefault(self.main_chain[i], 0))
    max
  # Process scoring
  var max_newchain_score = 0
  for i in countdown(sig.targets.len - 1, 0):
    let c = sig.targets[i]

    let slot = sig.slot - 1 - i
    var slot_key: array[4, byte]
    bigEndian32(slot_key.addr, slot.unsafeAddr)
    doAssert self.blocks[c].slot <= slot

    # If a parent and child block have non-consecutive slots, then the parent
    # block is also considered to be the canonical block at all of the intermediate
    # slot numbers. We store the scores for the block at each height separately
    var key: array[36, byte]
    key[0 ..< 4] = slot_key
    key[4 ..< 36] = c.data
    self.scores_at_height[key] = self.scores_at_height.getOrDefault(key, 0) + 1

    # For fork choice rule purposes, the score of a block is the highst score
    # that it has at any height
    self.scores[c] = max(self.scores.getOrDefault(c, 0), self.scores_at_height[key])

    # If 2/3 of notaries vote for a block, it is justified
    if self.scores_at_height[key] == NOTARIES * 2 div 3: # Shouldn't that be >= ?
      self.justified[c] = true
      var c2 = c
      self.log &"Justified: {slot} {($c)[0 ..< 8]}"

      # If EPOCH_LENGTH+1 blocks are justified in a row, the oldest is
      # considered finalized

      var finalize = true
      for slot2 in countdown(slot-1, max(slot - EPOCH_LENGTH * 1, 0)):
        # Note the max(...)-1 in spec is unneeded, Nim ranges are inclusive
        if slot2 < self.blocks[c2].slot:
          c2 = self.blocks[c2].parent_hash

        var slot_key2: array[4, byte]
        bigEndian32(slot_key2.addr, slot2.unsafeAddr)
        var key2: array[36, byte]
        key[0 ..< 4] = slot_key2
        key[4 ..< 36] = c2.data

        if self.scores_at_height.getOrDefault(key2, 0) < NOTARIES * 2 div 3:
          finalize = false
          self.log &"Not quite finalized: stopped at {slot2} needed {max(slot - EPOCH_LENGTH, 0)}"
          break

        if slot2 < slot - EPOCH_LENGTH - 1 and finalize and c2 notin self.finalized:
          self.log &"Finalized: {self.blocks[c2].slot} {($c)[0 ..< 8]}"
          self.finalized[c2] = true

    # Find the maximum score of a block on the chain that this sig is weighing on
    if self.blocks[c].slot > anc.slot:
      max_newchain_score = max(max_newchain_score, self.scores[c])

  # If it's higher, switch over the canonical chain
  if max_newchain_score > max_score:
    self.main_chain = self.mainchain[0 ..< anc.height + 1]
    self.recalculate_head()

  self.sigs[sig.hash] = sig

  # Rebroadcast
  self.network.broadcast(self, sig)

func get_sig_targets(self: Node, start_slot: int32): seq[Eth2Digest] =
  # Get the portion of the main chain that is within the last EPOCH_LENGTH
  # slots, once again duplicating the parent in cases where the parent and
  # child's slots are not consecutive
  result = @[]
  var i = self.main_chain.high
  for slot in countdown(start_slot-1, max(start_slot - EPOCH_LENGTH, 0)):
    # Note the max(...)-1 in spec is unneeded, Nim ranges are inclusive
    if slot < self.blocks[self.main_chain[i]].slot:
      dec i
    result.add self.main_chain[i]
  for i, x in result:
    doAssert self.blocks[x].slot <= start_slot - 1 - i
  doAssert result.len == min(EPOCH_LENGTH, start_slot)

proc tick*(self: Node) =
  self.timestamp += initDuration(milliseconds = 100)
  self.log &"Tick: {self.timestamp}", lvl=1
  # Make a block?
  let slot = int32 seconds(self.timestamp div SLOT_SIZE)
  if slot > self.last_made_block and (slot mod NOTARIES) == self.id:
    self.broadcast(
      initBlock(self.blocks[
        self.main_chain[^1]
        ], slot, self.id)
    )
    self.last_made_block = slot
  # Make a sig?
  if slot > self.last_made_sig and (slot mod EPOCH_LENGTH) == self.id mod EPOCH_LENGTH:
    var sig_from = self.main_chain.high
    while sig_from > 0 and self.blocks[self.main_chain[sig_from]].slot >= slot - EPOCH_LENGTH:
      dec sig_from
    let sig = newSig(self.id, self.get_sig_targets(slot), slot, self.timestamp)
    self.log &"Sig: {self.id} {sig.slot} {sig.targets.mapIt(($it)[0 ..< 4])}"
    self.broadcast sig
    self.last_made_sig = slot
  # process time queue
  while self.timequeue.len > 0 and self.timequeue[0].min_timestamp <= self.timestamp:
    self.on_receive(self.timequeue[0], reprocess = true)
    self.timequeue.delete(0) # This is expensive, but we can't use a queue due to random insertions in add_to_timequeue
