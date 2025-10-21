# beacon_chain
# Copyright (c) 2023-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Gnosis preset - Deneb
# https://github.com/gnosischain/specs/blob/5a3b1d21705d3cb79be95fcf9a9a1745faf10050/consensus/preset/gnosis/deneb.yaml
const
  # Misc
  # ---------------------------------------------------------------
  # `uint64(4096)`
  FIELD_ELEMENTS_PER_BLOB*: uint64 = 4096
  # `uint64(2**12)` (= 4096)
  MAX_BLOB_COMMITMENTS_PER_BLOCK*: uint64 = 4096
  # `floorlog2(get_generalized_index(BeaconBlockBody, 'blob_kzg_commitments')) + 1 + ceillog2(MAX_BLOB_COMMITMENTS_PER_BLOCK)` = 4 + 1 + 12 = 17
  KZG_COMMITMENT_INCLUSION_PROOF_DEPTH* = 17
