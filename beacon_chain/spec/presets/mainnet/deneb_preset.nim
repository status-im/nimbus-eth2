# Mainnet preset - Deneb
# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.5/presets/mainnet/deneb.yaml
const
  # `uint64(4096)`
  FIELD_ELEMENTS_PER_BLOB*: uint64 = 4096
  # `uint64(2**2)` (= 4)
  MAX_BLOBS_PER_BLOCK*: uint64 = 4
