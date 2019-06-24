type
  NetworkBackendType* = enum
    libp2pSpecBackend
    libp2pNativeBackend
    rlpxBackend

const
  network_type {.strdefine.} = "libp2p_native"

  networkBackend* = when network_type == "rlpx": rlpxBackend
                    elif network_type == "libp2p_spec": libp2pSpecBackend
                    elif network_type == "libp2p_native": libp2pNativeBackend
                    else: {.fatal: "The 'network_type' should be one of 'libp2p_spec', 'libp2p_native' or 'rlpx'" .}

const
  versionMajor* = 0
  versionMinor* = 2
  versionBuild* = 0

  semanticVersion* = 1
    # Bump this up every time a breaking change is introduced
    # Clients having different semantic versions won't be able
    # to join the same testnets.

template versionAsStr*: string =
  $versionMajor & "." & $versionMinor & "." & $versionBuild

proc fullVersionStr*: string =
  versionAsStr & "_" & network_type

