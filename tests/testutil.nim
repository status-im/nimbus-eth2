# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  testutils/markdown_reports,
  unittest2,
  ../beacon_chain/spec/presets

from std/algorithm import SortOrder, sort
from std/strformat import `&`
from std/tables import OrderedTable, `[]=`, initOrderedTable, mgetOrPut, sort
from std/times import Duration, inNanoseconds

export unittest2

type
  TestDuration = tuple[duration: float, label: string]

func preset*(): string {.compileTime.} =
  " [Preset: " & const_preset & ']'

var testTimes: seq[TestDuration]
var status = initOrderedTable[string, OrderedTable[string, Status]]()

type TimingCollector = ref object of OutputFormatter

func toFloatSeconds(duration: Duration): float =
  duration.inNanoseconds().float / 1_000_000_000.0

method testEnded*(formatter: TimingCollector, testResult: TestResult) =
  {.gcsafe.}: # Lie!
    status.mgetOrPut(testResult.suiteName, initOrderedTable[string, Status]())[testResult.testName] =
      case testResult.status
      of TestStatus.OK: Status.OK
      of TestStatus.FAILED: Status.Fail
      of TestStatus.SKIPPED: Status.Skip
    testTimes.add (testResult.duration.toFloatSeconds, testResult.testName)

proc summarizeLongTests*(name: string) =
  # TODO clean-up and make machine-readable/storable the output
  sort(testTimes, system.cmp, SortOrder.Descending)

  try:
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
  except CatchableError as exc:
    raiseAssert exc.msg

addOutputFormatter(new TimingCollector)
