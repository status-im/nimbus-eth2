# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

# Mainnet preset - Heze
# https://github.com/ethereum/consensus-specs/blob/v1.7.0-alpha.11/presets/mainnet/heze.yaml
const
  # Inclusion list committee
  # ---------------------------------------------------------------
  # 2**4 (= 16) validators
  INCLUSION_LIST_COMMITTEE_SIZE* = 16
