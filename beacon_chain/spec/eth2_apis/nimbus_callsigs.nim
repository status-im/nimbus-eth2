import
  callsigs_types

export callsigs_types

proc getBeaconHead(): Slot
proc getChainHead(): JsonNode
proc getSyncing(): bool
proc getNetworkPeerId(): string
proc getNetworkPeers(): seq[string]
proc getNodeVersion(): string
proc peers(): JsonNode
proc setLogLevel(level: string)
proc getEth1Chain(): JsonNode
proc getEth1ProposalData(): JsonNode
proc getChronosFutures(): JsonNode
proc getGossipSubPeers(): JsonNode
