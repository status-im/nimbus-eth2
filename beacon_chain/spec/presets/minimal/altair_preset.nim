# Mainnet preset - Altair
# https://github.com/ethereum/eth2.0-specs/blob/1d5c4ecffbadc70b62189cb4219be055b8efa2e9/presets/mainnet/altair.yaml
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
  # customized
  SYNC_COMMITTEE_SIZE* = 32
  # customized
  EPOCHS_PER_SYNC_COMMITTEE_PERIOD*: uint64 = 8


  # Sync protocol
  # ---------------------------------------------------------------
  # 1
  MIN_SYNC_COMMITTEE_PARTICIPANTS*: uint64 = 1
