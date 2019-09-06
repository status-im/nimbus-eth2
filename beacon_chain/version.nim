type
  NetworkBackendType* = enum
    libp2pBackend
    rlpxBackend

const
  network_type {.strdefine.} = "libp2p"

  networkBackend* = when network_type == "rlpx": rlpxBackend
                    elif network_type == "libp2p": libp2pBackend
                    else: {.fatal: "The 'network_type' should be either 'libp2p' or 'rlpx'" .}

const
  versionMajor* = 0
  versionMinor* = 3
  versionBuild* = 0

  semanticVersion* = 2
    # Bump this up every time a breaking change is introduced
    # Clients having different semantic versions won't be able
    # to join the same testnets.

  useInsecureFeatures* = true # defined(insecure)
    # TODO This is temporarily set to true, so it's easier for other teams to
    # launch the beacon_node with metrics enabled during the interop lock-in.
    # We'll disable it once the lock-in is over.

template versionAsStr*: string =
  $versionMajor & "." & $versionMinor & "." & $versionBuild

proc fullVersionStr*: string =
  versionAsStr & "_" & network_type

