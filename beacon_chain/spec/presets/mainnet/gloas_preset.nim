# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Mainnet preset - Gloas
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/presets/mainnet/gloas.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # 2**9 (= 512) validators
  PTC_SIZE* = 512

  # Max operations per block
  # ---------------------------------------------------------------
  # 2**2 (= 4) attestations
  MAX_PAYLOAD_ATTESTATIONS* = 4

  # Execution
  # ---------------------------------------------------------------
  # 2**8 (= 256) builder deposit requests
  MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD* = 256
  # 2**4 (= 16) builder exit requests
  MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD* = 16

  # Withdrawals processing
  # ---------------------------------------------------------------
  # 2**14 (= 16,384) builders
  MAX_BUILDERS_PER_WITHDRAWALS_SWEEP* = 16384

  # Type-specific SSZ bounds
  # ---------------------------------------------------------------
  # 16,829 bytes, ~16 KiB
  MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE*: uint64 = 16829
  # 2,097,616 bytes, ~2 MiB
  MAX_ATTESTER_SLASHING_SIZE*: uint64 = 2097616
  # 8,585,272 bytes, ~8 MiB
  MAX_DATA_COLUMN_SIDECAR_SIZE*: uint64 = 8585272
  # 8,585,741 bytes, ~8 MiB
  MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE*: uint64 = 8585741
  # 196,932 bytes, ~192 KiB
  MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE*: uint64 = 196932
  # 4,082,504 bytes, ~4 MiB
  MAX_SIGNED_BEACON_BLOCK_SIZE*: uint64 = 4082504
