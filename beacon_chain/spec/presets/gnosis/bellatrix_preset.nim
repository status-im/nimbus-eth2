# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Gnosis preset - Bellatrix
# https://github.com/gnosischain/specs/blob/1648fc86cef7bc148d74cb21921d2d12ca9442ac/consensus/preset/gnosis/bellatrix.yaml
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
