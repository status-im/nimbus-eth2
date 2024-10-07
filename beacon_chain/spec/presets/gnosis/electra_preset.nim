# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Gnosis preset - Electra (Gnosis version not avilable yet; EF mainnet for now)
# https://github.com/ethereum/consensus-specs/blob/v1.5.0-alpha.7/presets/mainnet/electra.yaml
const
  # Gwei values
  # ---------------------------------------------------------------
  # 2**5 * 10**9 (= 32,000,000,000) Gwei
  MIN_ACTIVATION_BALANCE* = 32000000000
  # 2**11 * 10**9 (= 2,048,000,000,000) Gwei
  MAX_EFFECTIVE_BALANCE_ELECTRA* = 2048000000000

  # State list lengths
  # ---------------------------------------------------------------
  # `uint64(2**27)` (= 134,217,728)
  PENDING_DEPOSITS_LIMIT*: uint64 = 134217728
  # `uint64(2**27)` (= 134,217,728)
  PENDING_PARTIAL_WITHDRAWALS_LIMIT*: uint64 = 134217728
  # `uint64(2**18)` (= 262,144)
  PENDING_CONSOLIDATIONS_LIMIT*: uint64 = 262144

  # Reward and penalty quotients
  # ---------------------------------------------------------------
  # `uint64(2**12)` (= 4,096)
  MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA*: uint64 = 4096
  # `uint64(2**12)` (= 4,096)
  WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA*: uint64 = 4096

  # # Max operations per block
  # ---------------------------------------------------------------
  # `uint64(2**0)` (= 1)
  MAX_ATTESTER_SLASHINGS_ELECTRA*: uint64 = 1
  # `uint64(2**3)` (= 8)
  MAX_ATTESTATIONS_ELECTRA*: uint64 = 8
  # `uint64(2**0)` (= 1)
  MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD*: uint64 = 1

  # Execution
  # ---------------------------------------------------------------
  # 2**13 (= 8192) deposit requests
  MAX_DEPOSIT_REQUESTS_PER_PAYLOAD* = 8192
  # 2**4 (= 16) withdrawal requests
  MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD* = 16

  # Withdrawals processing
  # ---------------------------------------------------------------
  # 2**3 ( = 8) pending withdrawals
  MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP* = 8

  # Pending deposits processing
  # ---------------------------------------------------------------
  # 2**4 ( = 4) pending deposits
  MAX_PENDING_DEPOSITS_PER_EPOCH* = 16
