# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Merkle tree helpers
# ---------------------------------------------------------------

# References:
#   - https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/test_libs/pyspec/eth2spec/utils/merkle_minimal.py
#   - https://github.com/ethereum/eth2.0-specs/blob/v0.8.1/specs/light_client/merkle_proofs.md
#   - merkleize template in ssz.nim
#   - Binary Indexed Trees / Fenwick Tree building:
#       https://github.com/numforge/laser/blob/2a167b37b7eba1fab89068c1bb61f48a9fb51b05/benchmarks/random_sampling/fenwicktree.nim#L67-L118

import
  # Specs
  ../../beacon_chain/spec/[datatypes, digest],
  # shims
  stew/bitops2

func nextPowerOf2*(x: int): int =
  ## Returns x if x is a power of 2
  ## or the next biggest power of 2
  1 shl (fastLog2(x.uint-1) + 1)

func merkleTreeFromLeaves(
        values: openarray[Eth2Digest],
        depth: static[int] = 32
      ): seq[Eth2Digest] =
  ## Depth should be the same as
  ## verify_merkle_branch / is_valid_merkle_branch

  # Note: Merkle Tree are indexed by 1 :/
  # https://github.com/ethereum/eth2.0-specs/issues/1008

  # A complete tree (all leaves used) with n leaves
  # has n-1 internal nodes, for a total of 2N-1 nodes
  # so we allocate enough to hold a complete tree

  # Tree relation in a flat sequence
  #                  root at 1
  # Left child        idx*2
  # Right child       idx*2 + 1
  # Parent            idx/2

  let n = values.len.nextPowerOfTwo()
  let leaves_offset = n # node0 is unused.
  let size = leaves_offset + n
  result = newSeq[Eth2Digest](size)

  # The leaves contain the values
  # the range [leaves_offset + values.len ..< leaves_offset + values.len.nextPowerOfTwo()]
  # is wasted. Sparse merkle trees would help there
  result[leaves_offset ..< leaves_offset + values.len] = values

  # Now we build the internal nodes
  for i in countdown(leaves_offset, 1):
    result[i] = withEth2Hash:
      h.update(result[2*i])
      h.update(result[2*i+1])
