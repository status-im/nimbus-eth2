# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

## This module implements the version tagging details of all binaries included
## in the Nimbus release process (i.e. beacon_node, validator_client, etc)

import std/[os, strutils], metrics

const sourcePath = currentSourcePath.rsplit({DirSep, AltSep}, 1)[0]

proc gitFolderExists(path: string): bool {.compileTime.} =
  # walk up parent folder to find `.git` folder
  var currPath = sourcePath
  while true:
    if dirExists(currPath & "/.git"):
      return true
    let parts = splitPath(currPath)
    if parts.tail.len == 0:
      break
    currPath = parts.head
  false

const
  compileYear = CompileDate[0 ..< 4] # YYYY-MM-DD (UTC)
  copyrights* =
    "Copyright (c) 2019-" & compileYear & " Status Research & Development GmbH"

  GitRevisionOverride {.strdefine.} = ""

  # strip: remove spaces
  # --short=8: ensure we get 8 chars of commit hash
  # -C sourcePath: get the correct git hash no matter where the current dir is.
  GitRevision* =
    when GitRevisionOverride.len > 0:
      static:
        doAssert(
          GitRevisionOverride.len == 8,
          "GitRevisionOverride must consist of 8 characters",
        )
        doAssert(
          GitRevisionOverride.allIt(it in HexDigits),
          "GitRevisionOverride should contains only hex chars",
        )

      GitRevisionOverride
    else:
      if gitFolderExists(sourcePath):
        # only using git if the parent dir is a git repo.
        strip(
          staticExec(
            "git -C " & strutils.escape(sourcePath) & " rev-parse --short=8 HEAD"
          )
        )
      else:
        # otherwise we use revision number given by build system.
        # e.g. user download from release tarball, or Github zip download.
        "00000000"

  nimFullBanner* = staticExec("nim --version")

func getNimGitHash(): string =
  const gitPrefix = "git hash: "
  let tmp = splitLines(nimFullBanner)
  if tmp.len == 0:
    return
  for line in tmp:
    if line.startsWith(gitPrefix) and line.len > 8 + gitPrefix.len:
      result = line[gitPrefix.len ..< gitPrefix.len + 8]

func nimBanner*(): string =
  let gitHash = getNimGitHash()
  let tmp = splitLines(nimFullBanner)
  if gitHash.len > 0:
    tmp[0] & " (" & gitHash & ")"
  else:
    tmp[0]

declareGauge nimVersionGauge, "Nim version info", ["version", "nim_commit"], name = "nim_version"
nimVersionGauge.set(1, labelValues=[NimVersion, getNimGitHash()])
