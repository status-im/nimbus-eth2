# beacon_chain
# Copyright (c) 2021-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

# Minimal preset - Altair
# https://github.com/ethereum/consensus-specs/blob/v1.6.0-beta.1/presets/minimal/altair.yaml
const
  # Rewards and penalties
  # ---------------------------------------------------------------
  # 3 * 2**24 (= 50,331,648)
  INACTIVITY_PENALTY_QUOTIENT_ALTAIR*: uint64 = 50331648
  # 2**6 (= 64)
  MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR*: uint64 = 64
  # 2
  PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR*: uint64 = 2

  # Sync committee
  # ---------------------------------------------------------------
  # [customized] 2**5 (= 32) participants
  SYNC_COMMITTEE_SIZE* = 32
  # [customized] 2**3 (= 8) epochs
  EPOCHS_PER_SYNC_COMMITTEE_PERIOD* {.intdefine.}: uint64 = 8

  # Sync protocol
  # ---------------------------------------------------------------
  # 2**0 (= 1) participants
  MIN_SYNC_COMMITTEE_PARTICIPANTS* = 1
  # [customized] SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD (= 8 * 8) epochs
  UPDATE_TIMEOUT*: uint64 = 64
