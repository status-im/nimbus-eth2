# Minimal preset - Capella
# https://github.com/ethereum/consensus-specs/blob/86e2f8fd7de25a7478c240f0cf5ba3c5264e96bf/presets/minimal/capella.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # # [customized] 16 for more interesting tests at low validator count
  MAX_PARTIAL_WITHDRAWALS_PER_EPOCH* = 16


  # State list lengths
  # ---------------------------------------------------------------
  # 2**40 (= 1,099,511,627,776) withdrawals
  WITHDRAWAL_QUEUE_LIMIT* = 1099511627776


  # Max operations per block
  # ---------------------------------------------------------------
  # 2**4 (= 16)
  MAX_BLS_TO_EXECUTION_CHANGES* = 16


  # Execution
  # ---------------------------------------------------------------
  # [customized] Lower than MAX_PARTIAL_WITHDRAWALS_PER_EPOCH so not all
  # processed in one block
  MAX_WITHDRAWALS_PER_PAYLOAD* = 8
