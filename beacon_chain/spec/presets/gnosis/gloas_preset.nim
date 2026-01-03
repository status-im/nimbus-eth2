# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Mainnet preset - Gloas (Gnosis version not available yet; EF mainnet for now)
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-alpha.6/presets/mainnet/gloas.yaml
const
  # Networking
  # ---------------------------------------------------------------
  # floorlog2(get_generalized_index(BeaconBlockBody, "signed_execution_payload_header", "message", "blob_kzg_commitments_root")) (= 9)
  KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH_GLOAS*: uint64 = 9

  # Execution
  # ---------------------------------------------------------------
  # 2**9 (= 512) validators
  PTC_SIZE*: uint64 = 512
  # 2**2 (= 4) attestations
  MAX_PAYLOAD_ATTESTATIONS*: uint64 = 4
