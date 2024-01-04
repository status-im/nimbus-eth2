# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Minimal preset - Bellatrix
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/presets/minimal/bellatrix.yaml
const
  # Updated penalty values
  # ---------------------------------------------------------------
  # 2**24 (= 16,777,216)
  INACTIVITY_PENALTY_QUOTIENT_BELLATRIX*: uint64 = 16777216
  # 2**5 (= 32)
  MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX*: uint64 = 32
  # 3
  PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX*: uint64 = 3


  # Execution
  # ---------------------------------------------------------------
  # 2**30 (= 1,073,741,824)
  MAX_BYTES_PER_TRANSACTION* = 1073741824
  # 2**20 (= 1,048,576)
  MAX_TRANSACTIONS_PER_PAYLOAD* = 1048576
  # 2**8 (= 256)
  BYTES_PER_LOGS_BLOOM* = 256
  # 2**5 (= 32)
  MAX_EXTRA_DATA_BYTES* = 32
