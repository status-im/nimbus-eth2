# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Mainnet preset - Electra
# https://github.com/ethereum/consensus-specs/blob/497d7999a606ddab0844e1702682500d3a339f83/presets/mainnet/electra.yaml
const
  # `uint64(2**0)` (= 1)
  MAX_ATTESTER_SLASHINGS_ELECTRA*: uint64 = 1
  # `uint64(2**3)` (= 8)
  MAX_ATTESTATIONS_ELECTRA*: uint64 = 8
  # 2**13 (= 8192) receipts
  MAX_DEPOSIT_RECEIPTS_PER_PAYLOAD* = 8192
  # 2**4 (= 16) exits
  MAX_EXECUTION_LAYER_EXITS* = 16
