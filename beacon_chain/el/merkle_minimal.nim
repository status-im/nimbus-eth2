# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/tests/core/pyspec/eth2spec/utils/merkle_minimal.py

# Merkle tree helpers
# ---------------------------------------------------------------

import
  sequtils,
  stew/endians2,
  # Specs
  ../spec/[eth2_merkleization, digest],
  ../spec/datatypes/base

template getProof*(
    proofs: seq[Eth2Digest], idxParam: int): openArray[Eth2Digest] =
  let
    idx = idxParam
    ## TODO: It's surprising that we have to do +1 here.
    ##       It seems that `depositContractLimit` is set too high.
    startIdx = idx * (DEPOSIT_CONTRACT_TREE_DEPTH + 1)
    endIdx = startIdx + DEPOSIT_CONTRACT_TREE_DEPTH - 1
  proofs.toOpenArray(startIdx, endIdx)

func attachMerkleProofs*(deposits: var openArray[Deposit]): Eth2Digest =
  let depositsRoots = mapIt(deposits, hash_tree_root(it.data))

  var merkleizer = createMerkleizer(DEPOSIT_CONTRACT_LIMIT)
  let proofs = merkleizer.addChunksAndGenMerkleProofs(depositsRoots)
  for i in 0 ..< depositsRoots.len:
    deposits[i].proof[0 ..< DEPOSIT_CONTRACT_TREE_DEPTH] = getProof(proofs, i)
    deposits[i].proof[DEPOSIT_CONTRACT_TREE_DEPTH] = default(Eth2Digest)
    deposits[i].proof[DEPOSIT_CONTRACT_TREE_DEPTH].data[0..7] =
      toBytesLE deposits.lenu64

  mixInLength(merkleizer.getFinalHash(), deposits.len)
