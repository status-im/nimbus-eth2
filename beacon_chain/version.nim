const
  useRLPx* = not defined(withLibP2P)

const
  versionMajor* = 0
  versionMinor* = 1
  versionBuild* = 10

template versionAsStr*: string =
  $versionMajor & "." & $versionMinor & "." & $versionBuild

proc fullVersionStr*: string =
  versionAsStr & (if useRLPx: " rlpx" else: " libp2p")
