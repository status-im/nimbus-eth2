const
  copyrights* = "Copyright (c) 2019 Status Research & Development GmbH"

  versionMajor* = 0
  versionMinor* = 3
  versionBuild* = 0

  semanticVersion* = 2
    # Bump this up every time a breaking change is introduced
    # Clients having different semantic versions won't be able
    # to join the same testnets.

  useInsecureFeatures* = defined(insecure)

  gitRevision* = staticExec("git rev-parse --short HEAD")

  nimBanner* = staticExec("nim --version")

  versionAsStr* =
    $versionMajor & "." & $versionMinor & "." & $versionBuild

  fullVersionStr* =
    versionAsStr & " (" & gitRevision & ")"

