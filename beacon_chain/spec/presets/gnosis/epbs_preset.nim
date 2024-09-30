# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Gnosis preset - epbs
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.5/specs/_features/eip7732/beacon-chain.md#preset
const
  # `2**2` (= 4)
  MAX_PAYLOAD_ATTESTATIONS*: uint8 = 4
  # `uint64(2**9)` (= 512)
  PTC_SIZE*: uint64 = 512

  # [TODO: Subject to change]
  # https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.4/specs/_features/eip7732/p2p-interface.md#preset
  KZG_COMMITMENT_INCLUSION_PROOF_DEPTH_EIP7732* = 13