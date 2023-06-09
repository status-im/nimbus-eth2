# Mainnet preset - Capella
# https://github.com/ethereum/consensus-specs/blob/v1.3.0/presets/mainnet/capella.yaml
const
  # Max operations per block
  # ---------------------------------------------------------------
  # 2**4 (= 16)
  MAX_BLS_TO_EXECUTION_CHANGES* = 16


  # Execution
  # ---------------------------------------------------------------
  # 2**4 (= 16) withdrawals
  MAX_WITHDRAWALS_PER_PAYLOAD* = 16


  # Withdrawals processing
  # ---------------------------------------------------------------
  # 2**14 (= 16384) validators
  MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP* = 16384
