# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Minimal preset - Capella
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-beta.5/presets/minimal/capella.yaml
const
  # Max operations per block
  # ---------------------------------------------------------------
  # 2**4 (= 16)
  MAX_BLS_TO_EXECUTION_CHANGES* = 16


  # Execution
  # ---------------------------------------------------------------
  # [customized] 2**2 (= 4)
  MAX_WITHDRAWALS_PER_PAYLOAD* = 4


  # Withdrawals processing
  # ---------------------------------------------------------------
  # [customized] 2**4 (= 16) validators
  MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP* = 16
