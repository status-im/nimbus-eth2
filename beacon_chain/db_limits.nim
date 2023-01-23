# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import spec/datatypes/constants

# No `uint64` support in Sqlite
template isSupportedBySQLite*(slot: Slot): bool =
  slot <= int64.high.Slot
template isSupportedBySQLite*(period: SyncCommitteePeriod): bool =
  period <= int64.high.SyncCommitteePeriod
