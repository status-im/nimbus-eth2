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
  tables, deques, strutils, hashes, times, # Stdlib
  nimcrypto                                # Nimble packages

const
  NOTARIES* = 100                        # Committee size in Casper v2.1
  SLOT_SIZE* = initDuration(seconds = 6) # Slot duration in Casper v2.1
  EPOCH_LENGTH* = 25                     # Cycle length in Casper v2.

# TODO, clear up if reference semantics are needed
# for the tables. I.e. what's their maximum size.

type
  BlockOrSig* = ref object of RootObj
    # For some reason, Block and Sig have to be stored
    # in an heterogenous container.
    # So we use inheritance to erase types

  BlockOrSigHash* = ref object of RootObj
  BlockHash* = ref object of BlockOrSigHash
    raw*: MDigest[256]
  SigHash* = ref object of BlockOrSigHash
    raw*: MDigest[384]

  Block* = ref object of BlockOrSig
    contents*: array[32, byte]
    parent_hash*: MDigest[256]
    hash*: MDigest[256]
    height*: int # slot in Casper v2.1 spec
    proposer*: int64
    slot*: int64
##########################################

func min_timestamp*(self: Block): Duration =
  SLOT_SIZE * self.slot

let Genesis* = Block()

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
    agents*: seq[int]
    latency_distribution_sample*: proc (): Duration
    time*: Duration
    objqueue*: TableRef[Duration, seq[(Node, BlockOrSig)]]
    peers*: TableRef[int, seq[Node]]
    reliability*: float

  Sig* = ref object of BlockOrSig
    # TODO: unsure if this is still relevant in Casper v2.1
    proposer*: int64                 # the validator that creates a block
    targets*: seq[MDigest[256]]      # the hash of blocks proposed
    slot*: int32                     # slot number
    timestamp*: int64                # ts in the ref implementation
    hash*: MDigest[384]              # The signature (BLS12-384)

  Node* = ref object
    blocks*: TableRef[MDigest[256], Block]
    sigs*: TableRef[MDigest[384], Sig]
    main_chain*: seq[MDigest[256]]
    timequeue*: seq[Block]
    parentqueue*: TableRef[MDigest[256], seq[BlockOrSig]]
    children*: TableRef[MDigest[256], seq[MDigest[256]]]
    scores*: TableRef[MDigest[256], int]
    scores_at_height*: TableRef[array[36, byte], int] # Should be slot not height in v2.1
    justified*: TableRef[MDigest[256], bool]
    finalized*: TableRef[MDigest[256], bool]
    timestamp*: Duration
    id*: int
    network*: NetworkSimulator
    used_parents*: TableRef[MDigest[256], Node]
    processed*: TableRef[BlockOrSigHash, BlockOrSig]
    sleepy*: bool
    careless*: bool
    first_round*: bool
    last_made_block*: int64
    last_made_sig*: int64
