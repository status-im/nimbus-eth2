# Minimal preset - EIP-4844
# https://github.com/ethereum/consensus-specs/blob/v1.3.0-rc.1/presets/minimal/eip4844.yaml
const
  # [customized]
  FIELD_ELEMENTS_PER_BLOB*: uint64 = 4
  # `uint64(2**2)` (= 4)
  MAX_BLOBS_PER_BLOCK*: uint64 = 4
