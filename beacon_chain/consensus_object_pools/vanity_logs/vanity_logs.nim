# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/os,
  chronicles

type
  LogProc = proc() {.gcsafe, raises: [].}

  VanityLogs* = object
    # Upon the merge activating, these get displayed, at least once when the
    # head becomes post-merge and then when the merge is finalized. If chain
    # reorgs happen around the initial merge onMergeTransitionBlock might be
    # called several times.
    onMergeTransitionBlock*: LogProc
    onFinalizedMergeTransitionBlock*: LogProc

    # Gets displayed on upgrade to Capella. May be displayed multiple times
    # in case of chain reorgs around the upgrade.
    onUpgradeToCapella*: LogProc

    # Gets displayed on when a BLS to execution change message for a validator
    # known by this node appears in a head block
    onKnownBlsToExecutionChange*: LogProc

    # Gets displayed on upgrade to Deneb. May be displayed multiple times
    # in case of chain reorgs around the upgrade.
    onUpgradeToDeneb*: LogProc

# Created by http://beatscribe.com/ (beatscribe#1008 on Discord)
# These need to be the main body of the log not to be reformatted or escaped.

proc bellatrixMono*()  = notice "\n" & staticRead("bellatrix" / "mono.txt")
proc bellatrixColor*() = notice "\n" & staticRead("bellatrix" / "color.ans")
proc bellatrixBlink*() = notice "\n" & staticRead("bellatrix" / "blink.ans")

proc capellaMono*()  = notice "\n" & staticRead("capella" / "mono.txt")
proc capellaColor*() = notice "\n" & staticRead("capella" / "color.ans")
proc capellaBlink*() = notice "\n" & staticRead("capella" / "blink.ans")

proc denebMono*()  = notice "\n" & staticRead("deneb" / "mono.txt")
proc denebColor*() = notice "\n" & staticRead("deneb" / "color.ans")
