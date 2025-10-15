# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

const
  MAXIMUM_GOSSIP_CLOCK_DISPARITY* {.intdefine.}: uint64 = 500  # hoodiUZH
  REORG_MAX_EPOCHS_SINCE_FINALIZATION* {.intdefine.}: uint64 = 2  # hoodiUZH
