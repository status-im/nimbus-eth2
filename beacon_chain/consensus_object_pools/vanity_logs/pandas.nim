# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import chronicles
from ".."/".."/conf import StdoutLogKind

type
  VanityLogs* = object
    onMergeTransitionBlock*:          proc() {.gcsafe, raises: [Defect].}
    onFinalizedMergeTransitionBlock*: proc() {.gcsafe, raises: [Defect].}

# Created by http://beatscribe.com/ (beatscribe#1008 on Discord)
# These need to be the main body of the log not to be reformatted or escaped.
proc mono🐼()  = notice "text-version.txt".staticRead
proc color🐼() = notice "color-version.ans".staticRead
proc blink🐼() = notice "blink-version.ans".staticRead

func getPandas*(stdoutKind: StdoutLogKind): VanityLogs =
  case stdoutKind
  of StdoutLogKind.Auto: raiseAssert "inadmissable here"
  of StdoutLogKind.Colors:
    VanityLogs(
      onMergeTransitionBlock:          color🐼,
      onFinalizedMergeTransitionBlock: blink🐼)
  of StdoutLogKind.NoColors:
    VanityLogs(
      onMergeTransitionBlock:          mono🐼,
      onFinalizedMergeTransitionBlock: mono🐼)
  of StdoutLogKind.Json, StdoutLogKind.None:
    VanityLogs(
      onMergeTransitionBlock:          (proc() = notice "🐼 Proof of Stake Activated 🐼"),
      onFinalizedMergeTransitionBlock: (proc() = notice "🐼 Proof of Stake Finalized 🐼"))
