# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[deques, tables, strformat],
  chronicles, metrics,
  ../beacon_chain_db,
  ../spec/[deposit_snapshots, digest, eth2_merkleization, forks, network],
  ../spec/datatypes/base,
  web3/[primitives, eth_api_types],
  ./merkle_minimal

export beacon_chain_db, deques, digest, base, forks

logScope:
  topics = "elchain"

declarePublicGauge eth1_finalized_head,
  "Block number of the highest Eth1 block finalized by Eth2 consensus"

declarePublicGauge eth1_finalized_deposits,
  "Number of deposits that were finalized by the Eth2 consensus"

declareGauge eth1_chain_len,
  "The length of the in-memory chain of Eth1 blocks"

type
  Eth1BlockNumber* = uint64
  Eth1BlockTimestamp* = uint64

  Eth1BlockObj* = object
    hash*: Eth2Digest
    number*: Eth1BlockNumber
    timestamp*: Eth1BlockTimestamp
      ## Basic properties of the block
      ## These must be initialized in the constructor

    deposits*: seq[DepositData]
      ## Deposits inside this particular block

    depositRoot*: Eth2Digest
    depositCount*: uint64
      ## Global deposits count and hash tree root of the entire sequence
      ## These are computed when the block is added to the chain (see `addBlock`)

  Eth1Block* = ref Eth1BlockObj

  Eth1Chain* = object
    db: BeaconChainDB
    cfg*: RuntimeConfig
    finalizedBlockHash*: Eth2Digest
    finalizedDepositsMerkleizer*: DepositsMerkleizer
      ## The latest block that reached a 50% majority vote from
      ## the Eth2 validators according to the follow distance and
      ## the ETH1_VOTING_PERIOD

    blocks*: Deque[Eth1Block]
      ## A non-forkable chain of blocks ending at the block with
      ## ETH1_FOLLOW_DISTANCE offset from the head.

    blocksByHash: Table[BlockHash, Eth1Block]

    headMerkleizer: DepositsMerkleizer
      ## Merkleizer state after applying all `blocks`

    hasConsensusViolation*: bool
      ## The local chain contradicts the observed consensus on the network

  BlockProposalEth1Data* = object
    vote*: Eth1Data
    deposits*: seq[Deposit]
    hasMissingDeposits*: bool

func asEth2Digest*(x: BlockHash): Eth2Digest =
  Eth2Digest(data: array[32, byte](x))

template asBlockHash*(x: Eth2Digest): BlockHash =
  BlockHash(x.data)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/validator.md#get_eth1_data
func compute_time_at_slot(genesis_time: uint64, slot: Slot): uint64 =
  genesis_time + slot * SECONDS_PER_SLOT

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/validator.md#get_eth1_data
func voting_period_start_time(state: ForkedHashedBeaconState): uint64 =
  let eth1_voting_period_start_slot =
    getStateField(state, slot) - getStateField(state, slot) mod
      SLOTS_PER_ETH1_VOTING_PERIOD.uint64
  compute_time_at_slot(
    getStateField(state, genesis_time), eth1_voting_period_start_slot)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/validator.md#get_eth1_data
func is_candidate_block(cfg: RuntimeConfig,
                        blk: Eth1Block,
                        period_start: uint64): bool =
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE <= period_start) and
  (blk.timestamp + cfg.SECONDS_PER_ETH1_BLOCK * cfg.ETH1_FOLLOW_DISTANCE * 2 >= period_start)

func shortLog*(b: Eth1Block): string =
  try:
    &"{b.number}:{shortLog b.hash}(deposits = {b.depositCount})"
  except ValueError as exc: raiseAssert exc.msg

template findBlock(chain: Eth1Chain, eth1Data: Eth1Data): Eth1Block =
  getOrDefault(chain.blocksByHash, asBlockHash(eth1Data.block_hash), nil)

func makeSuccessorWithoutDeposits*(existingBlock: Eth1Block,
                                   successor: BlockObject): Eth1Block =
  result = Eth1Block(
    hash: successor.hash.asEth2Digest,
    number: Eth1BlockNumber successor.number,
    timestamp: Eth1BlockTimestamp successor.timestamp)

func latestCandidateBlock(chain: Eth1Chain, periodStart: uint64): Eth1Block =
  for i in countdown(chain.blocks.len - 1, 0):
    let blk = chain.blocks[i]
    if is_candidate_block(chain.cfg, blk, periodStart):
      return blk

proc popFirst(chain: var Eth1Chain) =
  let removed = chain.blocks.popFirst
  chain.blocksByHash.del removed.hash.asBlockHash
  eth1_chain_len.set chain.blocks.len.int64

proc addBlock*(chain: var Eth1Chain, newBlock: Eth1Block) =
  for deposit in newBlock.deposits:
    chain.headMerkleizer.addChunk hash_tree_root(deposit).data

  newBlock.depositCount = chain.headMerkleizer.getChunkCount
  newBlock.depositRoot = chain.headMerkleizer.getDepositsRoot

  chain.blocks.addLast newBlock
  chain.blocksByHash[newBlock.hash.asBlockHash] = newBlock

  eth1_chain_len.set chain.blocks.len.int64

func toVoteData(blk: Eth1Block): Eth1Data =
  Eth1Data(
    deposit_root: blk.depositRoot,
    deposit_count: blk.depositCount,
    block_hash: blk.hash)

func hash*(x: Eth1Data): Hash =
  hash(x.block_hash)

proc pruneOldBlocks(chain: var Eth1Chain, depositIndex: uint64) =
  ## Called on block finalization to delete old and now redundant data.
  let initialChunks = chain.finalizedDepositsMerkleizer.getChunkCount
  var lastBlock: Eth1Block

  while chain.blocks.len > 0:
    let blk = chain.blocks.peekFirst
    if blk.depositCount >= depositIndex:
      break
    else:
      for deposit in blk.deposits:
        chain.finalizedDepositsMerkleizer.addChunk hash_tree_root(deposit).data
    chain.popFirst()
    lastBlock = blk

  if chain.finalizedDepositsMerkleizer.getChunkCount > initialChunks:
    chain.finalizedBlockHash = lastBlock.hash
    chain.db.putDepositContractSnapshot DepositContractSnapshot(
      eth1Block: lastBlock.hash,
      depositContractState: chain.finalizedDepositsMerkleizer.toDepositContractState,
      blockHeight: lastBlock.number)

    eth1_finalized_head.set lastBlock.number.toGaugeValue
    eth1_finalized_deposits.set lastBlock.depositCount.toGaugeValue

    debug "Eth1 blocks pruned",
           newTailBlock = lastBlock.hash,
           depositsCount = lastBlock.depositCount

func advanceMerkleizer(chain: Eth1Chain,
                       merkleizer: var DepositsMerkleizer,
                       depositIndex: uint64): bool =
  if chain.blocks.len == 0:
    return depositIndex == merkleizer.getChunkCount

  if chain.blocks.peekLast.depositCount < depositIndex:
    return false

  let
    firstBlock = chain.blocks[0]
    depositsInLastPrunedBlock = firstBlock.depositCount -
                                firstBlock.deposits.lenu64

  # advanceMerkleizer should always be called shortly after prunning the chain
  doAssert depositsInLastPrunedBlock == merkleizer.getChunkCount

  for blk in chain.blocks:
    for deposit in blk.deposits:
      if merkleizer.getChunkCount < depositIndex:
        merkleizer.addChunk hash_tree_root(deposit).data
      else:
        return true

  return merkleizer.getChunkCount == depositIndex

iterator getDepositsRange*(chain: Eth1Chain, first, last: uint64): DepositData =
  # TODO It's possible to make this faster by performing binary search that
  #      will locate the blocks holding the `first` and `last` indices.
  # TODO There is an assumption here that the requested range will be present
  #      in the Eth1Chain. This should hold true at the call sites right now,
  #      but we need to guard the pre-conditions better.
  for blk in chain.blocks:
    if blk.depositCount <= first:
      continue

    let firstDepositIdxInBlk = blk.depositCount - blk.deposits.lenu64
    if firstDepositIdxInBlk >= last:
      break

    for i in 0 ..< blk.deposits.lenu64:
      let globalIdx = firstDepositIdxInBlk + i
      if globalIdx >= first and globalIdx < last:
        yield blk.deposits[i]

func lowerBound(chain: Eth1Chain, depositCount: uint64): Eth1Block =
  # TODO: This can be replaced with a proper binary search in the
  #       future, but the `algorithm` module currently requires an
  #       `openArray`, which the `deques` module can't provide yet.
  for eth1Block in chain.blocks:
    if eth1Block.depositCount > depositCount:
      return
    result = eth1Block

proc trackFinalizedState*(chain: var Eth1Chain,
                          finalizedEth1Data: Eth1Data,
                          finalizedStateDepositIndex: uint64,
                          blockProposalExpected = false): bool =
  ## This function will return true if the ELManager is synced
  ## to the finalization point.

  if chain.blocks.len == 0:
    debug "Eth1 chain not initialized"
    return false

  let latest = chain.blocks.peekLast
  if latest.depositCount < finalizedEth1Data.deposit_count:
    if blockProposalExpected:
      error "The Eth1 chain is not synced",
            ourDepositsCount = latest.depositCount,
            targetDepositsCount = finalizedEth1Data.deposit_count
    return false

  let matchingBlock = chain.lowerBound(finalizedEth1Data.deposit_count)
  result = if matchingBlock != nil:
    if matchingBlock.depositRoot == finalizedEth1Data.deposit_root:
      true
    else:
      error "Corrupted deposits history detected",
            ourDepositsCount = matchingBlock.depositCount,
            targetDepositsCount = finalizedEth1Data.deposit_count,
            ourDepositsRoot = matchingBlock.depositRoot,
            targetDepositsRoot = finalizedEth1Data.deposit_root
      chain.hasConsensusViolation = true
      false
  else:
    error "The Eth1 chain is in inconsistent state",
          checkpointHash = finalizedEth1Data.block_hash,
          checkpointDeposits = finalizedEth1Data.deposit_count,
          localChainStart = shortLog(chain.blocks.peekFirst),
          localChainEnd = shortLog(chain.blocks.peekLast)
    chain.hasConsensusViolation = true
    false

  if result:
    chain.pruneOldBlocks(finalizedStateDepositIndex)

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.7/specs/phase0/validator.md#get_eth1_data
proc getBlockProposalData*(chain: var Eth1Chain,
                           state: ForkedHashedBeaconState,
                           finalizedEth1Data: Eth1Data,
                           finalizedStateDepositIndex: uint64): BlockProposalEth1Data =
  let
    periodStart = voting_period_start_time(state)
    hasLatestDeposits = chain.trackFinalizedState(finalizedEth1Data,
                                                  finalizedStateDepositIndex,
                                                  blockProposalExpected = true)

  var otherVotesCountTable = initCountTable[Eth1Data]()
  for vote in getStateField(state, eth1_data_votes):
    let eth1Block = chain.findBlock(vote)
    if eth1Block != nil and
       eth1Block.depositRoot == vote.deposit_root and
       vote.deposit_count >= getStateField(state, eth1_data).deposit_count and
       is_candidate_block(chain.cfg, eth1Block, periodStart):
      otherVotesCountTable.inc vote
    else:
      debug "Ignoring eth1 vote",
            root = vote.block_hash,
            deposits = vote.deposit_count,
            depositsRoot = vote.deposit_root,
            localDeposits = getStateField(state, eth1_data).deposit_count

  let
    stateDepositIdx = getStateField(state, eth1_deposit_index)
    stateDepositsCount = getStateField(state, eth1_data).deposit_count

  # A valid state should never have this condition, but it doesn't hurt
  # to be extra defensive here because we are working with uint types
  var pendingDepositsCount = if stateDepositsCount > stateDepositIdx:
    stateDepositsCount - stateDepositIdx
  else:
    0

  if otherVotesCountTable.len > 0:
    let (winningVote, votes) = otherVotesCountTable.largest
    debug "Voting on eth1 head with majority", votes
    result.vote = winningVote
    if uint64((votes + 1) * 2) > SLOTS_PER_ETH1_VOTING_PERIOD:
      pendingDepositsCount = winningVote.deposit_count - stateDepositIdx

  else:
    let latestBlock = chain.latestCandidateBlock(periodStart)
    if latestBlock == nil:
      debug "No acceptable eth1 votes and no recent candidates. Voting no change"
      result.vote = getStateField(state, eth1_data)
    else:
      debug "No acceptable eth1 votes. Voting for latest candidate"
      result.vote = latestBlock.toVoteData

  if pendingDepositsCount > 0:
    if hasLatestDeposits:
      let
        totalDepositsInNewBlock = min(MAX_DEPOSITS, pendingDepositsCount)
        postStateDepositIdx = stateDepositIdx + pendingDepositsCount
      var
        deposits = newSeqOfCap[DepositData](totalDepositsInNewBlock)
        depositRoots = newSeqOfCap[Eth2Digest](pendingDepositsCount)
      for data in chain.getDepositsRange(stateDepositIdx, postStateDepositIdx):
        if deposits.lenu64 < totalDepositsInNewBlock:
          deposits.add data
        depositRoots.add hash_tree_root(data)

      var scratchMerkleizer = chain.finalizedDepositsMerkleizer
      if chain.advanceMerkleizer(scratchMerkleizer, stateDepositIdx):
        let proofs = scratchMerkleizer.addChunksAndGenMerkleProofs(depositRoots)
        for i in 0 ..< totalDepositsInNewBlock:
          var proof: array[33, Eth2Digest]
          proof[0..31] = proofs.getProof(i.int)
          proof[32] = default(Eth2Digest)
          proof[32].data[0..7] = toBytesLE uint64(postStateDepositIdx)
          result.deposits.add Deposit(data: deposits[i], proof: proof)
      else:
        error "The Eth1 chain is in inconsistent state" # This should not really happen
        result.hasMissingDeposits = true
    else:
      result.hasMissingDeposits = true

func clear*(chain: var Eth1Chain) =
  chain.blocks.clear()
  chain.blocksByHash.clear()
  chain.headMerkleizer = chain.finalizedDepositsMerkleizer
  chain.hasConsensusViolation = false

proc init*(
    T: type Eth1Chain,
    cfg: RuntimeConfig,
    db: BeaconChainDB,
    depositContractBlockNumber: uint64,
    depositContractBlockHash: Eth2Digest): T =
  let
    (finalizedBlockHash, depositContractState) =
      if db != nil:
        let snapshot = db.getDepositContractSnapshot()
        if snapshot.isSome:
          (snapshot.get.eth1Block, snapshot.get.depositContractState)
        else:
          let oldSnapshot = db.getUpgradableDepositSnapshot()
          if oldSnapshot.isSome:
            (oldSnapshot.get.eth1Block, oldSnapshot.get.depositContractState)
          else:
            db.putDepositContractSnapshot DepositContractSnapshot(
              eth1Block: depositContractBlockHash,
              blockHeight: depositContractBlockNumber)
            (depositContractBlockHash, default(DepositContractState))
      else:
        (depositContractBlockHash, default(DepositContractState))
    m = DepositsMerkleizer.init(depositContractState)

  T(db: db,
    cfg: cfg,
    finalizedBlockHash: finalizedBlockHash,
    finalizedDepositsMerkleizer: m,
    headMerkleizer: m)
