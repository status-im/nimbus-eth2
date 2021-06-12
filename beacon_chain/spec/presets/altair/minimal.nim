# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# This file contains constants that are part of the spec and thus subject to
# serialization and spec updates.

const
  # Updated penalty values
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.7/presets/minimal/altair.yaml#L3
  CONFIG_NAME* = "minimal"

  INACTIVITY_PENALTY_QUOTIENT_ALTAIR* = 50331648 ##\
  ## 3 * 2**24 (= 50,331,648)

  MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR* = 64
  PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR* = 2

  # Sync protocol
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.7/presets/minimal/altair.yaml#L13
  SYNC_COMMITTEE_SIZE* = 32
  EPOCHS_PER_SYNC_COMMITTEE_PERIOD* = 8

  # Sync protocol
  # ---------------------------------------------------------------
  # https://github.com/ethereum/eth2.0-specs/blob/v1.1.0-alpha.7/presets/minimal/altair.yaml#L21
  MIN_SYNC_COMMITTEE_PARTICIPANTS* = 1
