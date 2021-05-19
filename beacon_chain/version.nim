# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import strutils

when not defined(nimscript):
  import times
  let copyrights* = "Copyright (c) 2019-" & $(now().utc.year) & " Status Research & Development GmbH"

const
  versionMajor* = 1
  versionMinor* = 3
  versionBuild* = 0

  versionBlob* = "stateofus" # Single word - ends up in the default graffitti

  gitRevision* = strip(staticExec("git rev-parse --short HEAD"))[0..5]

  nimBanner* = staticExec("nim --version | grep -v Compiled")

  versionAsStr* =
    $versionMajor & "." & $versionMinor & "." & $versionBuild

  fullVersionStr* = "v" & versionAsStr & "-" & gitRevision & "-" & versionBlob

func shortNimBanner*(): string =
  const gitPrefix = "git hash: "
  let tmp = splitLines(nimBanner)
  if tmp.len == 0:
    return
  var gitHash = ""
  for line in tmp:
    if line.startsWith(gitPrefix) and line.len > 8 + gitPrefix.len:
      gitHash = line[gitPrefix.len..<gitPrefix.len + 8]

  if gitHash.len > 0:
    tmp[0] & " (" & gitHash & ")"
  else:
    tmp[0]

