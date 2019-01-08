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
  tables, deques, strutils, hashes, times,
  random,
  # Nimble packages
  nimcrypto,
  ../../beacon_chain/spec/digest

const
  NOTARIES* = 100     # Committee size in Casper v2.1
  SLOT_SIZE* = 6      # Slot duration in Casper v2.1
  EPOCH_LENGTH* = 25  # Cycle length in Casper v2.

# TODO, clear up if reference semantics are needed
# for the tables. I.e. what's their maximum size.

type
  BlockOrSig* = ref object of RootObj
    # For some reason, Block and Sig have to be stored
    # in an heterogenous container.
    # So we use inheritance to erase types

  BlockOrSigHash* = ref object of RootObj
  BlockHash* = ref object of BlockOrSigHash
    raw*: Eth2Digest
  SigHash* = ref object of BlockOrSigHash
    raw*: MDigest[384]

  Block* = ref object of BlockOrSig
    contents*: array[32, byte]
    parent_hash*: Eth2Digest
    hash*: Eth2Digest
    height*: int # slot in Casper v2.1 spec
    proposer*: int32
    slot*: int32
##########################################

func min_timestamp*(self: Block): Duration =
  const slot_size = initDuration(seconds = SLOT_SIZE)
  result = slot_size * self.slot

let Genesis* = Block()

proc initBlock*(parent: Block, slot, proposer: int32): Block =
  new result
  for val in result.contents.mitems:
    val = rand(0.byte .. 7.byte)
  if not parent.isNil:
    result.parent_hash = parent.hash
    result.height = parent.height + 1

  var ctx: keccak256
  ctx.init()
  ctx.update(result.parent_hash.data)
  ctx.update(result.contents)
  ctx.finish(result.hash.data)
  ctx.clear()

  doAssert slot mod NOTARIES == proposer
  result.proposer = proposer
  result.slot = slot

##########################################

func hash*(x: MDigest): Hash =
  ## Allow usage of MDigest in hashtables
  # We just keep the first 64 bits of the digest
  const bytes = x.type.bits div 8
  const nb_ints = bytes div sizeof(int) # Hash is a distinct int

  result = cast[array[nb_ints, Hash]](x)[0]
  # Alternatively hash for real
  # result = x.unsafeAddr.hashData(bytes)

method hash*(x: BlockOrSigHash): Hash {.base.}=
  raise newException(ValueError, "Not implemented error. Please implement in child types")

method hash*(x: BlockHash): Hash =
  ## Allow usage of Blockhash in tables
  x.raw.hash

method hash*(x: SigHash): Hash =
  ## Allow usage of Sighash in tables
  x.raw.hash

func hash*(x: Duration): Hash =
  ## Allow usage of Duration in tables
  # Due to rpivate fields, we use pointer + length as a hack:
  # https://github.com/nim-lang/Nim/issues/8857
  result = hashData(x.unsafeAddr, x.sizeof)

#########################################

type
  NetworkSimulator* = ref object
    agents*: seq[Node]
    latency_distribution_sample*: proc (): Duration
    time*: Duration
    objqueue*: TableRef[Duration, seq[tuple[recipient: Node, obj: BlockOrSig]]]
    peers*: TableRef[int, seq[Node]]
    reliability*: float

  Sig* = ref object of BlockOrSig
    # TODO: unsure if this is still relevant in Casper v2.1
    proposer*: int64                 # the validator that creates a block
    targets*: seq[Eth2Digest]      # the hash of blocks proposed
    slot*: int32                     # slot number
    timestamp*: Duration             # ts in the ref implementation
    hash*: MDigest[384]              # The signature (BLS12-384)

  Node* = ref object
    blocks*: TableRef[Eth2Digest, Block]
    sigs*: TableRef[MDigest[384], Sig]
    main_chain*: seq[Eth2Digest]
    timequeue*: seq[Block]
    parentqueue*: TableRef[Eth2Digest, seq[BlockOrSig]]
    children*: TableRef[Eth2Digest, seq[Eth2Digest]]
    scores*: TableRef[Eth2Digest, int]
    scores_at_height*: TableRef[array[36, byte], int] # Should be slot not height in v2.1
    justified*: TableRef[Eth2Digest, bool]
    finalized*: TableRef[Eth2Digest, bool]
    timestamp*: Duration
    id*: int32
    network*: NetworkSimulator
    used_parents*: TableRef[Eth2Digest, Node]
    processed*: TableRef[BlockOrSigHash, BlockOrSig]
    sleepy*: bool
    careless*: bool
    first_round*: bool
    last_made_block*: int32
    last_made_sig*: int32

proc newSig*(
        proposer: int32,
        targets: seq[Eth2Digest],
        slot: int32,
        ts: Duration): Sig =
  new result
  result.proposer = proposer
  result.targets = targets
  result.slot = slot
  result.timestamp = ts
  for val in result.hash.data.mitems:
    val = rand(0.byte .. 7.byte)

proc newNode*(
    id: int32,
    network: NetworkSimulator,
    sleepy, careless = false,
    timestamp = DurationZero
  ): Node =
  new result
  result.id = id
  result.network = network
  result.timestamp = timestamp
  result.sleepy = sleepy
  result.careless = careless
  result.main_chain = @[Genesis.hash]
  result.blocks = {Genesis.hash: Genesis}.newTable

  # Boilerplate empty initialization
  result.processed = newTable[BlockOrSigHash, BlockOrSig]()
  result.children = newTable[Eth2Digest, seq[Eth2Digest]]()
  result.parentqueue = newTable[Eth2Digest, seq[BlockOrSig]]()
  result.scores = newTable[Eth2Digest, int]()
  result.scores_at_height = newTable[array[36, byte], int]()
  result.sigs = newTable[MDigest[384], Sig]()
  result.justified = newTable[Eth2Digest, bool]()

###########################################################
# Forward declarations

method on_receive*(self: Node, obj: BlockOrSig, reprocess = false) {.base.} =
  raise newException(ValueError, "Not implemented error. Please implement in child types")

###########################################################

###########################################################
# Common

func broadcast*(self: NetworkSimulator, sender: Node, obj: BlockOrSig) =
  for p in self.peers[sender.id]:
    let recv_time = self.time + self.latency_distribution_sample()
    if recv_time notin self.objqueue:
      self.objqueue[recv_time] = @[]
    self.objqueue[recv_time].add (p, obj)

###########################################################
