# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  json_serialization/std/net,
  ./conf

export net, conf

type LightClientConf* = object
  # Config
  configFile* {.
    desc: "Loads the configuration from a TOML file"
    name: "config-file" .}: Option[InputFile]

  # Logging
  logLevel* {.
    desc: "Sets the log level"
    defaultValue: "INFO"
    name: "log-level" .}: string

  logStdout* {.
    hidden
    desc: "Specifies what kind of logs should be written to stdout (auto, colors, nocolors, json)"
    defaultValueDesc: "auto"
    defaultValue: StdoutLogKind.Auto
    name: "log-format" .}: StdoutLogKind

  logFile* {.
    desc: "Specifies a path for the written Json log file (deprecated)"
    name: "log-file" .}: Option[OutFile]

  # Storage
  dataDir* {.
    desc: "The directory where nimbus will store all blockchain data"
    defaultValue: config.defaultDataDir()
    defaultValueDesc: ""
    abbr: "d"
    name: "data-dir" .}: OutDir

  # Network
  eth2Network* {.
    desc: "The Eth2 network to join"
    defaultValueDesc: "mainnet"
    name: "network" .}: Option[string]

  # Libp2p
  bootstrapNodes* {.
    desc: "Specifies one or more bootstrap nodes to use when connecting to the network"
    abbr: "b"
    name: "bootstrap-node" .}: seq[string]

  bootstrapNodesFile* {.
    desc: "Specifies a line-delimited file of bootstrap Ethereum network addresses"
    defaultValue: ""
    name: "bootstrap-file" .}: InputFile

  listenAddress* {.
    desc: "Listening address for the Ethereum LibP2P and Discovery v5 traffic"
    defaultValue: defaultListenAddress
    defaultValueDesc: $defaultListenAddressDesc
    name: "listen-address" .}: IpAddress

  tcpPort* {.
    desc: "Listening TCP port for Ethereum LibP2P traffic"
    defaultValue: defaultEth2TcpPort
    defaultValueDesc: $defaultEth2TcpPortDesc
    name: "tcp-port" .}: Port

  udpPort* {.
    desc: "Listening UDP port for node discovery"
    defaultValue: defaultEth2TcpPort
    defaultValueDesc: $defaultEth2TcpPortDesc
    name: "udp-port" .}: Port

  maxPeers* {.
    desc: "The target number of peers to connect to"
    defaultValue: 160 # 5 (fanout) * 64 (subnets) / 2 (subs) for a heathy mesh
    name: "max-peers" .}: int

  hardMaxPeers* {.
    desc: "The maximum number of peers to connect to. Defaults to maxPeers * 1.5"
    name: "hard-max-peers" .}: Option[int]

  nat* {.
    desc: "Specify method to use for determining public address. " &
          "Must be one of: any, none, upnp, pmp, extip:<IP>"
    defaultValue: NatConfig(hasExtIp: false, nat: NatAny)
    defaultValueDesc: "any"
    name: "nat" .}: NatConfig

  enrAutoUpdate* {.
    desc: "Discovery can automatically update its ENR with the IP address " &
          "and UDP port as seen by other nodes it communicates with. " &
          "This option allows to enable/disable this functionality"
    defaultValue: false
    name: "enr-auto-update" .}: bool

  enableYamux* {.
    hidden
    desc: "Enable the Yamux multiplexer"
    defaultValue: false
    name: "enable-yamux" .}: bool

  agentString* {.
    defaultValue: "nimbus",
    desc: "Node agent string which is used as identifier in network"
    name: "agent-string" .}: string

  discv5Enabled* {.
    desc: "Enable Discovery v5"
    defaultValue: true
    name: "discv5" .}: bool

  directPeers* {.
    desc: "The list of priviledged, secure and known peers to connect and maintain the connection to, this requires a not random netkey-file. In the complete multiaddress format like: /ip4/<address>/tcp/<port>/p2p/<peerId-public-key>. Peering agreements are established out of band and must be reciprocal."
    name: "direct-peer" .}: seq[string]

  # Light client
  trustedBlockRoot* {.
    desc: "Recent trusted finalized block root to initialize light client from"
    name: "trusted-block-root" .}: Eth2Digest

  # Execution layer
  web3Urls* {.
    desc: "One or more execution layer Engine API URLs"
    name: "web3-url" .}: seq[EngineApiUrlConfigValue]

  elUrls* {.
    desc: "One or more execution layer Engine API URLs"
    name: "el" .}: seq[EngineApiUrlConfigValue]

  noEl* {.
    defaultValue: false
    desc: "Don't use an EL. The node will remain optimistically synced and won't be able to perform validator duties"
    name: "no-el" .}: bool

  jwtSecret* {.
    desc: "A file containing the hex-encoded 256 bit secret key to be used for verifying/generating JWT tokens"
    name: "jwt-secret" .}: Option[InputFile]

  bandwidthEstimate* {.
    hidden
    desc: "Bandwidth estimate for the node (bits per second)"
    name: "debug-bandwidth-estimate" .}: Option[Natural]

  # Testing
  stopAtEpoch* {.
    hidden
    desc: "The wall-time epoch at which to exit the program. (for testing purposes)"
    defaultValue: 0
    name: "debug-stop-at-epoch" .}: uint64

template databaseDir*(config: LightClientConf): string =
  config.dataDir.databaseDir

template loadJwtSecret*(
    rng: var HmacDrbgContext,
    config: LightClientConf,
    allowCreate: bool): Option[seq[byte]] =
  rng.loadJwtSecret(string(config.dataDir), config.jwtSecret, allowCreate)

proc engineApiUrls*(config: LightClientConf): seq[EngineApiUrl] =
  let elUrls = if config.noEl:
    return newSeq[EngineApiUrl]()
  elif config.elUrls.len == 0 and config.web3Urls.len == 0:
    @[getDefaultEngineApiUrl(config.jwtSecret)]
  else:
    config.elUrls

  (elUrls & config.web3Urls).toFinalEngineApiUrls(
    config.jwtSecret.configJwtSecretOpt)
