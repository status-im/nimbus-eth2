# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

## This module implements the version tagging details of all binaries included
## in the Nimbus release process (i.e. beacon_node, validator_client, etc)

{.push raises: [].}

import std/[strutils, compilesettings]

const
  compileYear = CompileDate[0 ..< 4]  # YYYY-MM-DD (UTC)
  copyrights* =
    "Copyright (c) 2019-" & compileYear & " Status Research & Development GmbH"

  versionMajor* = 24
  versionMinor* = 1
  versionBuild* = 1

  versionBlob* = "stateofus" # Single word - ends up in the default graffiti

  ## You can override this if you are building the
  ## sources outside the git tree of Nimbus:
  git_revision_override* {.strdefine.} =
    when querySetting(SingleValueSetting.command) == "check":
      # The staticExec call below returns an empty string
      # when `nim check` is used and this leads to a faux
      # compile-time error.
      # We work-around the problem with this override and
      # save some time in executing the external command.
      "123456"
    else:
      ""

  gitRevisionLong* = when git_revision_override.len == 0:
    staticExec "git rev-parse --short HEAD"
  else:
    git_revision_override

  gitRevision* = strip(gitRevisionLong)[0..5]

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
