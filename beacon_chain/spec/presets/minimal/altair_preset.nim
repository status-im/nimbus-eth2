# Minimal preset - Altair
# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/presets/minimal/altair.yaml
const
  # Updated penalty values
  # ---------------------------------------------------------------
  # 3 * 2**24 (= 50,331,648)
  INACTIVITY_PENALTY_QUOTIENT_ALTAIR*: uint64 = 50331648
  # 2**6 (= 64)
  MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR*: uint64 = 64
  # 2
  PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR*: uint64 = 2


  # Sync committee
  # ---------------------------------------------------------------
  # [customized]
  SYNC_COMMITTEE_SIZE* = 32
  # [customized]
  EPOCHS_PER_SYNC_COMMITTEE_PERIOD* {.intdefine.}: uint64 = 8


  # Sync protocol
  # ---------------------------------------------------------------
  # 1
  MIN_SYNC_COMMITTEE_PARTICIPANTS* = 1
  # SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD (= 8 * 8)
  UPDATE_TIMEOUT*: uint64 = 64
