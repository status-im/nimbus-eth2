# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import chronicles
from std/strutils import find
from ".."/".."/conf import StdoutLogKind

type
  PandaTexts* = object
    headPanda*:      proc() {.gcsafe, raises: [Defect].}
    finalizedPanda*: proc() {.gcsafe, raises: [Defect].}

template removeLastLine(🐼Text: string): string =
  # Part of the artwork, but not during runtime display.
  🐼Text[0 ..< 🐼Text.find("SAUCE")]

template read🐼(🐼File: string): string =
  🐼File.staticRead.removeLastLine

# These need to be the main body of the log not to be reformatted or escaped.
proc mono🐼()  = notice "text-version.txt".read🐼
proc color🐼() = notice "color-version.txt".read🐼
proc blink🐼() = notice "blink-version.txt".read🐼

func getPandas*(stdoutKind: StdoutLogKind): PandaTexts =
  case stdoutKind
  of StdoutLogKind.Auto: raiseAssert "inadmissable here"
  of StdoutLogKind.Colors:
    PandaTexts(headPanda: color🐼, finalizedPanda: blink🐼)
  of StdoutLogKind.NoColors:
    PandaTexts(headPanda: mono🐼,  finalizedPanda: mono🐼)
  of StdoutLogKind.Json, StdoutLogKind.None:
    PandaTexts(
      headPanda:      (proc() = notice "Proof of Stake Activated"),
      finalizedPanda: (proc() = notice "Proof of Stake Finalized"))
