# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  os, algorithm, strformat, stats, times, tables, std/monotimes, stew/endians2,
  testutils/markdown_reports, chronicles,
  ../beacon_chain/[beacon_chain_db, extras],
  ../beacon_chain/ssz,
  ../beacon_chain/spec/[digest, beaconstate, datatypes, presets],
  ../beacon_chain/consensus_object_pools/blockchain_dag,
  eth/db/[kvstore, kvstore_sqlite3],
  testblockutil

export beacon_chain_db

type
  TestDuration = tuple[duration: float, label: string]

func preset*(): string =
  " [Preset: " & const_preset & ']'

# For state_sim
template withTimer*(duration: var float, body: untyped) =
  let start = getMonoTime()

  block:
    body

  duration = (getMonoTime() - start).inMicroseconds.float / 1000000.0

# For state_sim
template withTimerRet*(stats: var RunningStat, body: untyped): untyped =
  let start = getMonoTime()
  let tmp = block:
    body
  let stop = getMonoTime()
  stats.push (stop - start).inMicroseconds.float / 1000000.0

  tmp

var testTimes: seq[TestDuration]
var status = initOrderedTable[string, OrderedTable[string, Status]]()
var last: string

proc summarizeLongTests*(name: string) =
  # TODO clean-up and make machine-readable/storable the output
  # TODO this is too hard-coded and mostly a demo for using the
  # timedTest wrapper template for unittest
  sort(testTimes, system.cmp, SortOrder.Descending)

  echo ""
  echo "10 longest individual test durations"
  echo "------------------------------------"
  for i, item in testTimes:
    echo &"{item.duration:6.2f}s for {item.label}"
    if i >= 10:
      break

  status.sort do (a: (string, OrderedTable[string, Status]),
                  b: (string, OrderedTable[string, Status])) -> int: cmp(a[0], b[0])

  generateReport(name & "-" & const_preset, status, width=90)

template suiteReport*(name, body) =
  last = name
  status[last] = initOrderedTable[string, Status]()
  block: # namespacing
    proc runSuite() =
      suite name:
        body
    runSuite()

template timedTest*(name, body) =
  var f: float
  test name:
    status[last][name] = Status.Fail

    withTimer f:
      body

    status[last][name] = case testStatusIMPL
                         of OK: Status.OK
                         of FAILED: Status.Fail
                         of SKIPPED: Status.Skip

  # TODO reached for a failed test; maybe defer or similar
  # TODO noto thread-safe as-is
  testTimes.add (f, name)

proc makeTestDB*(tailState: var BeaconState, tailBlock: SignedBeaconBlock): BeaconChainDB =
  result = BeaconChainDB.new(defaultRuntimePreset, "", inMemory = true)
  ChainDAGRef.preInit(result, tailState, tailState, tailBlock)

proc makeTestDB*(validators: Natural): BeaconChainDB =
  let
    genState = initialize_beacon_state(
      defaultRuntimePreset,
      Eth2Digest(),
      0,
      makeInitialDeposits(validators.uint64, flags = {skipBlsValidation}),
      {skipBlsValidation})
    genBlock = get_initial_beacon_block(genState[])
  makeTestDB(genState[], genBlock)

export inMicroseconds
