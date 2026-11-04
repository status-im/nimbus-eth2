# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Gnosis preset - EIP8321
# https://github.com/lukassta/consensus-specs/blob/12c8b24bc09b12f62688d439ba20ef00b1fdfe1f/presets/mainnet/eip8321.yaml
const
  # Hash-chain RANDAO
  # ---------------------------------------------------------------
  # 3 (= MIN_SEED_LOOKAHEAD + 2)
  COMMITMENT_REGISTRATION_DELAY* = 3
  # 2**7 (= 128)
  MAX_RANDAO_COMMITMENT_REGISTRATIONS* = 128
