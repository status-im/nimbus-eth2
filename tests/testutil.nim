# beacon_chain
# Copyright (c) 2018-2019 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  stats, stew/endians2,
  chronicles, eth/trie/[db],
  ../beacon_chain/[beacon_chain_db, block_pool, ssz, beacon_node_types],
  ../beacon_chain/spec/datatypes

func preset*(): string =
  " [Preset: " & const_preset & ']'

template withTimer*(stats: var RunningStat, body: untyped) =
  let start = getMonoTime()

  block:
    body

  let stop = getMonoTime()
  stats.push (stop - start).inMicroseconds.float / 1000000.0

template withTimerRet*(stats: var RunningStat, body: untyped): untyped =
  let start = getMonoTime()
  let tmp = block:
    body
  let stop = getMonoTime()
  stats.push (stop - start).inMicroseconds.float / 1000000.0

  tmp

proc makeTestDB*(tailState: BeaconState, tailBlock: BeaconBlock): BeaconChainDB =
  result = init(BeaconChainDB, newMemoryDB())
  BlockPool.preInit(result, tailState, tailBlock)
