# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest, ./testutil,
  chronos/timer,
  ../beacon_chain/time

suiteReport "Time utilities":
  timedTest "humaneStr":
    check:
      humaneStr(2.weeks) == "2 weeks"
      humaneStr(2.weeks + 2.days) == "2 weeks"
      humaneStr(2.weeks + 7.days) == "3 weeks"
      humaneStr(1.weeks + 3.days) == "10 days"
      humaneStr(1.weeks + 3.days + 2.hours) == "10 days"
      humaneStr(5.days + 3.hours) == "5 days"
      humaneStr(1.days + 3.hours + 10.minutes) == "27 hours 10 minutes"
      humaneStr(1.days + 15.seconds + 342.milliseconds) == "24 hours 15 seconds"
      humaneStr(12.hours + 2.minutes + 12.seconds + 342.milliseconds) == "12 hours 2 minutes 12 seconds"
      humaneStr(4.seconds + 342.milliseconds) == "4.342 seconds"
      humaneStr(2.seconds) == "2 seconds"
      humaneStr(1.seconds) == "1 second"
      humaneStr(1.seconds + 12.milliseconds) == "1.012 seconds"
      humaneStr(1320.milliseconds) == "1.320 seconds"
      humaneStr(1000.milliseconds) == "1 second"
      humaneStr(124.milliseconds) == "124 milliseconds"
      humaneStr(312.nanoseconds) == "312 nanoseconds"
      humaneStr(123431.nanoseconds) == "123 microseconds"

