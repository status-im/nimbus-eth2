type
  NetworkBackendType* = enum
    libp2p
    libp2pDaemon

const
  NETWORK_TYPE {.strdefine.} = "libp2p_daemon"

  networkBackend* = when NETWORK_TYPE == "libp2p": libp2p
                    elif NETWORK_TYPE == "libp2p_daemon": libp2pDaemon
                    else: {.fatal: "The 'NETWORK_TYPE' should be either 'libp2p', 'libp2p_daemon'" .}

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

  versionAsStr* =
    $versionMajor & "." & $versionMinor & "." & $versionBuild

  fullVersionStr* =
    versionAsStr & " (" & gitRevision & ", " & NETWORK_TYPE & ")"

