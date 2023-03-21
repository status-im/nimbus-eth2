# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## This module implements the version tagging details of all binaries included
## in the Nimbus release process (i.e. beacon_node, validator_client, etc)

{.push raises: [].}

import strutils

when not defined(nimscript):
  import times
  let copyrights* = "Copyright (c) 2019-" & $(now().utc.year) & " Status Research & Development GmbH"

const
  versionMajor* = 23
  versionMinor* = 3
  versionBuild* = 2

  versionBlob* = "stateofus" # Single word - ends up in the default graffiti

  gitRevision* = strip(staticExec("git rev-parse --short HEAD"))[0..5]

  nimFullBanner* = staticExec("nim --version")
  nimBanner* = staticExec("nim --version | grep Version")

  versionAsStr* =
    $versionMajor & "." & $versionMinor & "." & $versionBuild

  fullVersionStr* = "v" & versionAsStr & "-" & gitRevision & "-" & versionBlob

func getNimGitHash*(): string =
  const gitPrefix = "git hash: "
  let tmp = splitLines(nimFullBanner)
  if tmp.len == 0:
    return
  for line in tmp:
    if line.startsWith(gitPrefix) and line.len > 8 + gitPrefix.len:
      result = line[gitPrefix.len..<gitPrefix.len + 8]

func shortNimBanner*(): string =
  let gitHash = getNimGitHash()
  let tmp = splitLines(nimFullBanner)
  if gitHash.len > 0:
    tmp[0] & " (" & gitHash & ")"
  else:
    tmp[0]
