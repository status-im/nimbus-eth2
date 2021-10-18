# beacon_chain
# Copyright (c) 2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  ../spec/forks,
  ../beacon_chain_db

proc putState*(db: BeaconChainDB, state: ForkedHashedBeaconState) =
  case state.kind:
  of BeaconStateFork.Phase0: db.putState(getStateRoot(state), state.phase0Data.data)
  of BeaconStateFork.Altair: db.putState(getStateRoot(state), state.altairData.data)
  of BeaconStateFork.Merge:  db.putState(getStateRoot(state), state.mergeData.data)
