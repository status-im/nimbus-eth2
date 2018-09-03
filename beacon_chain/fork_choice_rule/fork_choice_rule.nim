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
  tables, deques,   # Stdlib
  nimcrypto,        # Nimble packages
  # ../datatypes, # BeaconBlock is still different from the simulation blocks
  ./networksim      # From repo

import hashes
func hash(x: MDigest): Hash =
  # Allow usage of MDigest in hashtables
  const bytes = x.type.bits div 8
  result = x.unsafeAddr.hashData(bytes)

const
  NOTARIES = 100    # Committee size in Casper v2.1
  SLOT_SIZE = 6     # Slot duration in Casper v2.1
  EPOCH_LENGTH = 25 # Cycle length inCasper v2.

    # TODO, clear up if reference semantics are needed
    # for the tables, Block and Sig

type
  Block = ref object
    contents: array[32, byte]
    parent_hash: MDigest[256]
    hash: MDigest[256]
    height: int # slot in Casper v2.1 spec
    proposer: int64
    slot: int64

func min_timestamp(self: Block): int64 =
  SLOT_SIZE * self.slot

let Genesis = Block()

type
  Sig = object
    # TODO: unsure if this is still relevant in Casper v2.1
    proposer: int64                 # the validator that creates a block
    targets: seq[MDigest[256]]      # the hash of blocks proposed
    slot: int64                     # slot number
    timestamp: int64                # ts in the ref implementation
    hash: MDigest[384]              # The signature (BLS12-384)

type
  Node = ref object

    blocks: TableRef[MDigest[256], Block]
    sigs: TableRef[MDigest[384], Sig]
    main_chain: seq[MDigest[256]]
    timequeue: seq[Block]
    parentqueue: TableRef[MDigest[256], Node]
    children: TableRef[MDigest[256], seq[MDigest[256]]]
    scores: TableRef[MDigest[256], int]
    scores_at_height: TableRef[MDigest[256], int] # Should be slot not height in v2.1
    justified: TableRef[MDigest[256], bool]
    finalized: TableRef[MDigest[256], bool]
    timestamp: int64
    id: int64
    network: NetworkSimulator
    used_parents: TableRef[MDigest[256], Node]
    processed: TableRef[MDigest[256], Block]
    sleepy: bool
    careless: bool
    first_round: bool
    last_made_block: int64
    last_made_sig: int64

proc log(self: Node, words: string, lvl = 3, all = false) =
  if (self.id == 0 or all) and lvl >= 2:
    echo self.id, words

func add_to_timequeue(self: Node, obj: Block) =
  var i = 0
  while i < self.timequeue.len and self.timequeue[i].min_timestamp < obj.min_timestamp:
    inc i
  self.timequeue.insert(obj, i)

func add_to_multiset[K, V](self: Node, multiset: var TableRef[K, V], k: K, v: V) =
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
