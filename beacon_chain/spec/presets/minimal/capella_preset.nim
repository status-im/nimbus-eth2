# Minimal preset - Capella
# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/presets/minimal/capella.yaml
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
