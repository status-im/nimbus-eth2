# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Minimal preset - Gloas
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/presets/minimal/gloas.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # [customized] 2**4 (= 16) validators
  PTC_SIZE* = 16

  # Max operations per block
  # ---------------------------------------------------------------
  # 2**2 (= 4) attestations
  MAX_PAYLOAD_ATTESTATIONS* = 4

  # Execution
  # ---------------------------------------------------------------
  # 2**6 (= 64) builder deposit requests
  MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD* = 64
  # 2**4 (= 16) builder exit requests
  MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD* = 16

  # Withdrawals processing
  # ---------------------------------------------------------------
  # [customized] 2**4 (= 16) builders
  MAX_BUILDERS_PER_WITHDRAWALS_SWEEP* = 16

  # Type-specific SSZ bounds
  # ---------------------------------------------------------------
  # 1,462 bytes, ~1 KiB
  MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE*: uint64 = 1462
  # [customized] 131,536 bytes, ~128 KiB
  MAX_ATTESTER_SLASHING_SIZE*: uint64 = 131536
  # 8,585,272 bytes, ~8 MiB
  MAX_DATA_COLUMN_SIDECAR_SIZE*: uint64 = 8585272
  # 8,585,741 bytes, ~8 MiB
  MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE*: uint64 = 8585741
  # 196,932 bytes, ~192 KiB
  MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE*: uint64 = 196932
