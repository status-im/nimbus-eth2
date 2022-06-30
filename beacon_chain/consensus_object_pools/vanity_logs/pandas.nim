# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import chronicles

type
  VanityLogs* = object
    onMergeTransitionBlock*:          proc() {.gcsafe, raises: [Defect].}
    onFinalizedMergeTransitionBlock*: proc() {.gcsafe, raises: [Defect].}

# Created by http://beatscribe.com/ (beatscribe#1008 on Discord)
# These need to be the main body of the log not to be reformatted or escaped.
proc mono🐼*()  = notice "\n" & "text-version.txt".staticRead
proc color🐼*() = notice "\n" & "color-version.ans".staticRead
proc blink🐼*() = notice "\n" & "blink-version.ans".staticRead
