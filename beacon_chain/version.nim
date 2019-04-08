const
  useRLPx* = not defined(withLibP2P)

const
  versionMajor* = 0
  versionMinor* = 1
  versionBuild* = 10

  semanticVersion* = 0
    # Bump this up every time a breaking change is introduced
    # Clients having different semantic versions won't be able
    # to join the same testnets.

template versionAsStr*: string =
  $versionMajor & "." & $versionMinor & "." & $versionBuild

proc fullVersionStr*: string =
  versionAsStr & (if useRLPx: " rlpx" else: " libp2p")
