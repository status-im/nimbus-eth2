# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Minimal preset - Fulu
# https://github.com/ethereum/consensus-specs/blob/v1.6.0/presets/minimal/fulu.yaml
const
  # Networking
  # ---------------------------------------------------------------
  # floorlog2(get_generalized_index(BeaconBlockBody, 'blob_kzg_commitments')) (= 4)
  KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH*: uint64 = 4

  # Blob
  # ---------------------------------------------------------------
  # 2**6 (= 64) field elements
  FIELD_ELEMENTS_PER_CELL*: uint64 = 64
  # 2**1 * FIELD_ELEMENTS_PER_BLOB (= 8,192) field elements
  FIELD_ELEMENTS_PER_EXT_BLOB*: uint64 = 8192
  # FIELD_ELEMENTS_PER_EXT_BLOB // FIELD_ELEMENTS_PER_CELL (= 128) cells
  CELLS_PER_EXT_BLOB* = 128
  # CELLS_PER_EXT_BLOB (= 128) columns
  NUMBER_OF_COLUMNS* = 128
