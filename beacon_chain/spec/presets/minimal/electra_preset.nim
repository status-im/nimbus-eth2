# beacon_chain
# Copyright (c) 2024-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Minimal preset - Electra
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/presets/minimal/electra.yaml
const
  # Gwei values
  # ---------------------------------------------------------------
  # 2**5 * 10**9 (= 32,000,000,000) Gwei
  MIN_ACTIVATION_BALANCE* = 32000000000
  # 2**11 * 10**9 (= 2,048,000,000,000) Gwei
  MAX_EFFECTIVE_BALANCE_ELECTRA*: uint64 = 2048000000000'u64

  # Rewards and penalties
  # ---------------------------------------------------------------
  # 2**12 (= 4,096)
  MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA*: uint64 = 4096
  # 2**12 (= 4,096)
  WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA*: uint64 = 4096

  # State list lengths
  # ---------------------------------------------------------------
  # 2**27 (= 134,217,728) pending deposits
  PENDING_DEPOSITS_LIMIT*: uint64 = 134217728
  # [customized] 2**6 (= 64) pending partial withdrawals
  PENDING_PARTIAL_WITHDRAWALS_LIMIT*: uint64 = 64
  # [customized] 2**6 (= 64) pending consolidations
  PENDING_CONSOLIDATIONS_LIMIT*: uint64 = 64

  # Max operations per block
  # ---------------------------------------------------------------
  # 2**0 (= 1) attester slashings
  MAX_ATTESTER_SLASHINGS_ELECTRA*: uint64 = 1
  # 2**3 (= 8) attestations
  MAX_ATTESTATIONS_ELECTRA*: uint64 = 8

  # Execution
  # ---------------------------------------------------------------
  # 2**13 (= 8,192) deposit requests
  MAX_DEPOSIT_REQUESTS_PER_PAYLOAD* = 8192
  # 2**4 (= 16) withdrawal requests
  MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD* = 16
  # 2**1 (= 2) consolidation requests
  MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD* = 2

  # Withdrawals processing
  # ---------------------------------------------------------------
  # [customized] 2**1 (= 2) pending withdrawals
  MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP* = 2

  # Pending deposits processing
  # ---------------------------------------------------------------
  # 2**4 (= 16) pending deposits
  MAX_PENDING_DEPOSITS_PER_EPOCH* = 16
