# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

type
  # "state" is already taken by BeaconState
  BeaconNodeStatus* = enum
    Starting
    Running
    Stopping

# this needs to be global, so it can be set in the Ctrl+C signal handler
var bnStatus* = BeaconNodeStatus.Starting
