# beacon_chain
# Copyright (c) 2022-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import chronicles

from std/os import `/`

type
  LogProc* = proc() {.gcsafe, raises: [].}

  VanityLogs* = object
    # Gets displayed on when a BLS to execution change message for a validator
    # known by this node appears in a head block
    onKnownBlsToExecutionChange*: LogProc

    # Gets displayed on upgrade to Deneb. May be displayed multiple times
    # in case of chain reorgs around the upgrade.
    onUpgradeToDeneb*: LogProc

    # Gets displayed on upgrade to Electra. May be displayed multiple times
    # in case of chain reorgs around the upgrade.
    onUpgradeToElectra*: LogProc

    # Gets displayed on a change to compounding for a validator known to the
    # known in a head block.
    onKnownCompoundingChange*: LogProc

    # Gets displayed on upgrade to Fulu. May be displayed multiple times
    # in case of chain reorgs around the upgrade.
    onUpgradeToFulu*: LogProc

    # Gets displayed on a blob parameters update.
    # May be displayed multiple times in case of chain reorgs.
    onBlobParametersUpdate*: LogProc

# Created by https://beatscribe.com (beatscribe#1008 on Discord)
# These need to be the main body of the log not to be reformatted or escaped.
#
# Policy: Retain retired art files in the directory, but don't link them anymore

proc capellaMono*()  = notice "\n" & staticRead("capella" / "mono.txt")
proc capellaBlink*() = notice "\n" & staticRead("capella" / "blink.ans")

proc denebMono*()  = notice "\n" & staticRead("deneb" / "mono.txt")
proc denebColor*() = notice "\n" & staticRead("deneb" / "color.ans")

proc electraMono*()  = notice "\n" & staticRead("electra" / "mono.txt")
proc electraColor*() = notice "\n" & staticRead("electra" / "color.ans")
proc electraBlink*() = notice "\n" & staticRead("electra" / "blink.ans")

proc fuluMono*()  = notice "\n" & staticRead("fulu" / "mono.txt")
proc fuluColor*() = notice "\n" & staticRead("fulu" / "color.ans")
