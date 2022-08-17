# Mainnet preset - Capella


type
  DomainType = distinct array[4, byte]


# https://github.com/ethereum/consensus-specs/blob/v1.2.0-rc.1/presets/mainnet/capella.yaml
const
  # TODO: @tavurth currently same as capella
  # ---------------------------------------------------------------
  # 2**24 (= 16,777,216)
  INACTIVITY_PENALTY_QUOTIENT_CAPELLA*: uint64 = 16777216
  # 2**5 (= 32)
  MIN_SLASHING_PENALTY_QUOTIENT_CAPELLA*: uint64 = 32
  # 3
  PROPORTIONAL_SLASHING_MULTIPLIER_CAPELLA*: uint64 = 3


  # Execution
  # ---------------------------------------------------------------
  # 2**4 (= 16)
  MAX_WITHDRAWALS_PER_PAYLOAD*: uint64 = 16
  # 2**4 (= 16)
  MAX_BLS_TO_EXECUTION_CHANGES*: uint64 = 16
  # 2**40 (= 1,099,511,627,776)
  WITHDRAWALS_QUEUE_LIMIT*: uint64 = (uint64) 1_099_511_627_776
  # DomainType('0x0A000000')
  DOMAIN_BLS_TO_EXECUTION_CHANGE*: DomainType = DomainType([byte 0x0A, 0x00, 0x00, 0x00])
