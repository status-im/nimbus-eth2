{.push raises: [Defect].}

import strutils

when not defined(nimscript):
  import times
  let copyrights* = "Copyright (c) 2019-" & $(now().utc.year) & " Status Research & Development GmbH"

const
  versionMajor* = 0
  versionMinor* = 5
  versionBuild* = 0

  useInsecureFeatures* = defined(insecure)

  gitRevision* = staticExec("git rev-parse --short HEAD")

  nimBanner* = staticExec("nim --version")

  versionAsStr* =
    $versionMajor & "." & $versionMinor & "." & $versionBuild

  fullVersionStr* =
    versionAsStr & " (" & gitRevision & ")"

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
