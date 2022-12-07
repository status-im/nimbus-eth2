from std/sequtils import all
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

  DepositTreeSnapshot* = object
    ## https://eips.ethereum.org/EIPS/eip-4881
    eth1Block*: Eth2Digest
    depositContractState*: DepositContractState
    blockHeight*: uint64

func toDepositTreeSnapshot*(d: OldDepositContractSnapshot,
                            blockHeight: uint64): DepositTreeSnapshot =
  DepositTreeSnapshot(
    eth1Block: d.eth1Block,
    depositContractState: d.depositContractState,
    blockHeight: blockHeight)

func toOldDepositContractSnapshot*(d: DepositTreeSnapshot): OldDepositContractSnapshot =
  OldDepositContractSnapshot(eth1Block: d.eth1Block,
                             depositContractState: d.depositContractState)

template getDepositCountU64*(d: OldDepositContractSnapshot |
                                DepositTreeSnapshot): uint64 =
  depositCountU64(d.depositContractState.deposit_count)

func getDepositRoot*(d: OldDepositContractSnapshot |
                        DepositTreeSnapshot): Eth2Digest =
  let merk = DepositsMerkleizer.init(d.depositContractState)
  let hash = merk.getFinalHash()
  # TODO: mixInLength should accept unsigned int instead of int as
  # this right now cuts in half the theoretical number of deposits.
  return mixInLength(hash, int(merk.totalChunks))

func isValid*(d: DepositTreeSnapshot, wantedDepositRoot: Eth2Digest): bool =
  ## `isValid` requires the snapshot to be self-consistent and
  ## to point to a specific Ethereum block
  return not (d.eth1Block.isZeroMemory or
              d.blockHeight == 0 or
              d.getDepositRoot() != wantedDepositRoot)

func matches*(snapshot: DepositTreeSnapshot, eth1_data: Eth1Data): bool =
  snapshot.getDepositCountU64() == eth1_data.deposit_count and
  snapshot.getDepositRoot() == eth1_data.deposit_root
