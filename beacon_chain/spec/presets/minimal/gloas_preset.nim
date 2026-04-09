# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Minimal preset - Gloas
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.1/presets/minimal/gloas.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # [customized] 2**1 (= 2) validators
  PTC_SIZE* = 2

  # Max operations per block
  # ---------------------------------------------------------------
  # 2**2 (= 4) attestations
  MAX_PAYLOAD_ATTESTATIONS* = 4

  # State list lengths
  # ---------------------------------------------------------------
  # 2**40 (= 1,099,511,627,776) builder spots
  BUILDER_REGISTRY_LIMIT* = 1099511627776
  # 2**20 (= 1,048,576) builder pending withdrawals
  BUILDER_PENDING_WITHDRAWALS_LIMIT* = 1048576

  # Withdrawals processing
  # ---------------------------------------------------------------
  # [customized] 2**4 (= 16) builders
  MAX_BUILDERS_PER_WITHDRAWALS_SWEEP* = 16
