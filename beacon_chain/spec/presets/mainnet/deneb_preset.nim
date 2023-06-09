# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Mainnet preset - Deneb
# https://github.com/ethereum/consensus-specs/blob/v1.4.0-alpha.1/presets/mainnet/deneb.yaml
const
  # `uint64(4096)`
  FIELD_ELEMENTS_PER_BLOB*: uint64 = 4096
  # `uint64(2**12)` (= 4096)
  MAX_BLOB_COMMITMENTS_PER_BLOCK*: uint64 = 4096
  # `uint64(2**2)` (= 4)
  MAX_BLOBS_PER_BLOCK*: uint64 = 4
