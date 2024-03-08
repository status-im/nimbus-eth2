# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

from stew/objects import isZeroMemory

import ./eth2_merkleization
from ./datatypes/base import Eth1Data, DepositContractState
from ./digest import Eth2Digest

export
  depositCountBytes, depositCountU64

type
  OldDepositContractSnapshot* = object
    eth1Block*: Eth2Digest
    depositContractState*: DepositContractState

  DepositContractSnapshot* = object
    eth1Block*: Eth2Digest
    depositContractState*: DepositContractState
    blockHeight*: uint64

func toDepositContractSnapshot*(
    d: OldDepositContractSnapshot,
    blockHeight: uint64): DepositContractSnapshot =
  DepositContractSnapshot(
    eth1Block: d.eth1Block,
    depositContractState: d.depositContractState,
    blockHeight: blockHeight)

func toOldDepositContractSnapshot*(
    d: DepositContractSnapshot): OldDepositContractSnapshot =
  OldDepositContractSnapshot(
    eth1Block: d.eth1Block,
    depositContractState: d.depositContractState)

template getDepositCountU64*(
    d: OldDepositContractSnapshot | DepositContractSnapshot): uint64 =
  depositCountU64(d.depositContractState.deposit_count)

func getDepositRoot*(
    d: OldDepositContractSnapshot | DepositContractSnapshot): Eth2Digest =
  var merk = DepositsMerkleizer.init(d.depositContractState)
  let hash = merk.getFinalHash()
  # TODO: mixInLength should accept unsigned int instead of int as
  # this right now cuts in half the theoretical number of deposits.
  return mixInLength(hash, int(merk.getChunkCount()))

func isValid*(d: DepositContractSnapshot, wantedDepositRoot: Eth2Digest): bool =
  ## `isValid` requires the snapshot to be self-consistent and
  ## to point to a specific Ethereum block
  not d.eth1Block.isZeroMemory and d.getDepositRoot() == wantedDepositRoot

func matches*(snapshot: DepositContractSnapshot, eth1_data: Eth1Data): bool =
  snapshot.getDepositCountU64() == eth1_data.deposit_count and
  snapshot.getDepositRoot() == eth1_data.deposit_root

# https://eips.ethereum.org/EIPS/eip-4881
func getExpandedBranch(
    finalized: FinalizedDepositTreeBranch,
    deposit_count: uint64
): Opt[array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]] =
  var
    branch: array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]
    idx = finalized.len
  for i in 0 ..< DEPOSIT_CONTRACT_TREE_DEPTH:
    if (deposit_count and (1'u64 shl i)) != 0:
      dec idx
      branch[i] = finalized[idx]
  if idx != 0:
    return Opt.none array[DEPOSIT_CONTRACT_TREE_DEPTH, Eth2Digest]
  Opt.some branch

func init(
    T: type DepositsMerkleizer,
    finalized: FinalizedDepositTreeBranch,
    deposit_root: Eth2Digest,
    deposit_count: uint64): Opt[DepositsMerkleizer] =
  let branch = ? getExpandedBranch(finalized, deposit_count)
  var res = Opt.some DepositsMerkleizer.init(branch, deposit_count)
  if res.get().getDepositsRoot() != deposit_root:
    res.reset()
  res

func init*(
    T: type DepositsMerkleizer,
    snapshot: DepositTreeSnapshot): Opt[DepositsMerkleizer] =
  DepositsMerkleizer.init(
    snapshot.finalized, snapshot.deposit_root, snapshot.deposit_count)

func init*(
    T: type DepositContractSnapshot,
    snapshot: DepositTreeSnapshot): Opt[DepositContractSnapshot] =
  var res = Opt.some DepositContractSnapshot(
    eth1Block: snapshot.execution_block_hash,
    depositContractState: DepositContractState(
      branch: ? getExpandedBranch(snapshot.finalized, snapshot.deposit_count),
      deposit_count: depositCountBytes(snapshot.deposit_count)),
    blockHeight: snapshot.execution_block_height)
  if not res.get.isValid(snapshot.deposit_root):
    res.reset()
  res

func getFinalizedBranch(
    branch: openArray[Eth2Digest],
    deposit_count: uint64): FinalizedDepositTreeBranch =
  doAssert branch.len == DEPOSIT_CONTRACT_TREE_DEPTH
  var
    finalized: FinalizedDepositTreeBranch
    i = branch.high
  while i > 0:
    dec i
    if (deposit_count and (1'u64 shl i)) != 0:
      doAssert finalized.add branch[i.int]
  finalized

func getFinalizedBranch(
    merkleizer: DepositsMerkleizer): FinalizedDepositTreeBranch =
  let chunks = merkleizer.getCombinedChunks()
  doAssert chunks.len == DEPOSIT_CONTRACT_TREE_DEPTH + 1
  getFinalizedBranch(
    chunks[0 ..< DEPOSIT_CONTRACT_TREE_DEPTH],
    merkleizer.getChunkCount())

func getTreeSnapshot*(
    merkleizer: var DepositsMerkleizer,
    execution_block_hash: Eth2Digest,
    execution_block_height: uint64): DepositTreeSnapshot =
  DepositTreeSnapshot(
    finalized: merkleizer.getFinalizedBranch(),
    deposit_root: merkleizer.getDepositsRoot(),
    deposit_count: merkleizer.getChunkCount(),
    execution_block_hash: execution_block_hash,
    execution_block_height: execution_block_height)

func getTreeSnapshot*(
    snapshot: DepositContractSnapshot): DepositTreeSnapshot =
  let deposit_count = snapshot.getDepositCountU64()
  DepositTreeSnapshot(
    finalized: getFinalizedBranch(
      snapshot.depositContractState.branch, deposit_count),
    deposit_root: snapshot.getDepositRoot(),
    deposit_count: deposit_count,
    execution_block_hash: snapshot.eth1Block,
    execution_block_height: snapshot.blockHeight)
