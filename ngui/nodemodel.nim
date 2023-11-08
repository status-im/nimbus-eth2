import NimQml

import
  std/[sequtils, json, times],
  ../beacon_chain/spec/eth2_apis/rest_beacon_client,
  ./attestationlist, ./utils
template xxx(body): string =
  try:
    $(body)
  except CatchableError as exc:
    exc.msg

QtObject:
  type
    NodeModel* = ref object of QObject
      client: RestClientRef
      genesis: string
      heads: string
      identity: string
      version: string
      health: string

  proc delete*(self: NodeModel) =
    self.QObject.delete

  proc setup*(self: NodeModel) =
    self.QObject.setup

  proc newNodeModel*(client: RestClientRef): NodeModel =
    let res = NodeModel(client: client)
    res.setup()
    res

  proc getgenesis*(self: NodeModel): string {.slot.} = self.genesis
  proc genesisChanged*(self: NodeModel, v: string) {.signal.}
  proc setgenesis*(self: NodeModel, v: string) =
    self.genesis = v
    self.genesisChanged(v)
  QtProperty[string] genesis:
    read = getgenesis
    notify = genesisChanged
    write = setgenesis

  proc getheads*(self: NodeModel): string {.slot.} = self.heads
  proc headsChanged*(self: NodeModel, v: string) {.signal.}
  proc setheads*(self: NodeModel, v: string) =
    self.heads = v
    self.headsChanged(v)
  QtProperty[string] heads:
    read = getheads
    notify = headsChanged
    write = setheads

  proc getidentity*(self: NodeModel): string {.slot.} = self.identity
  proc identityChanged*(self: NodeModel, v: string) {.signal.}
  proc setidentity*(self: NodeModel, v: string) =
    self.identity = v
    self.identityChanged(v)
  QtProperty[string] identity:
    read = getidentity
    notify = identityChanged
    write = setidentity

  proc getversion*(self: NodeModel): string {.slot.} = self.version
  proc versionChanged*(self: NodeModel, v: string) {.signal.}
  proc setversion*(self: NodeModel, v: string) =
    self.version = v
    self.versionChanged(v)
  QtProperty[string] version:
    read = getversion
    notify = versionChanged
    write = setversion

  proc gethealth*(self: NodeModel): string {.slot.} = self.health
  proc healthChanged*(self: NodeModel, v: string) {.signal.}
  proc sethealth*(self: NodeModel, v: string) =
    self.health = v
    self.healthChanged(v)
  QtProperty[string] health:
    read = gethealth
    notify = healthChanged
    write = sethealth

  proc update*(self: NodeModel) {.slot.} =
    self.setgenesis(xxx(waitFor(self.client.getGenesis()).data.data))
    self.setheads(xxx(waitFor(self.client.getDebugChainHeadsV2()).data.data.mapIt(
      toBlockLink(it.root) & " @ " & $it.slot
    ).join("\n")))
    self.setidentity(xxx(waitFor(self.client.getNetworkIdentity()).data.data))
    self.setversion(xxx(waitFor(self.client.getNodeVersion()).data.data.version))
    self.sethealth(xxx(waitFor(self.client.getHealth())))
