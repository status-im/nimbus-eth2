# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Minimal preset - PQ
# https://github.com/ethereum/consensus-specs/blob/a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c/presets/minimal/pq.yaml
const
  # Misc
  # ---------------------------------------------------------------
  MAX_COMMITTEES_PER_SLOT_PQ*: uint64 = 4

  # Time parameters
  # ---------------------------------------------------------------
  # 2**1 (= 2) slots
  MIN_ATTESTATION_INCLUSION_DELAY_PQ*: uint64 = 2

  # XMSS
  # ---------------------------------------------------------------
  # 2**20 (= 1,048,576)
  MAX_STARK_PROOF_SIZE*: uint64 = 1048576

  # Max operations per block
  # ---------------------------------------------------------------
  # 2**4 (= 16)
  MAX_ATTESTATIONS_PQ*: uint64 = 16

  # Execution
  # ---------------------------------------------------------------
  # 2**6 (= 64)
  MAX_VALIDATOR_PREREGISTRATION_REQUESTS_PER_PAYLOAD*: uint64 = 64
  # 2**2 (= 4)
  MAX_BUILDER_PREREGISTRATION_REQUESTS_PER_PAYLOAD*: uint64 = 4
  # 2**4 (= 16)
  MAX_VOLUNTARY_EXIT_REQUESTS_PER_PAYLOAD*: uint64 = 16
  # EIP-8205
  PREREGISTRATIONS_LIMIT*: uint64 = 64
  PREREGISTRATION_EXPIRY_SLOTS*: uint64 = 64

  # Type-specific SSZ bounds
  # ---------------------------------------------------------------
  MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE_PQ*: uint64 = 1052158
  MAX_ATTESTER_SLASHING_SIZE_PQ*: uint64 = 2228504
  MAX_SIGNED_EXECUTION_PAYLOAD_BID_SIZE_PQ*: uint64 = 199240
