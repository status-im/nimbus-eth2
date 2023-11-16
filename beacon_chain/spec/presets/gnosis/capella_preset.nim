# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Gnosis preset - Capella
# https://github.com/gnosischain/specs/blob/1648fc86cef7bc148d74cb21921d2d12ca9442ac/consensus/preset/gnosis/capella.yaml
const
  # Max operations per block
  # ---------------------------------------------------------------
  # 2**4 (= 16)
  MAX_BLS_TO_EXECUTION_CHANGES* = 16


  # Execution
  # ---------------------------------------------------------------
  # 2**3 (= 8) withdrawals
  MAX_WITHDRAWALS_PER_PAYLOAD* = 8


  # Withdrawals processing
  # ---------------------------------------------------------------
  # 2**13 (= 8192) validators
  MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP* = 8192
