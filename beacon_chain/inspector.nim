# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import strutils, os, tables
import confutils, chronicles, chronos, libp2p/daemon/daemonapi,
       libp2p/multiaddress
import stew/byteutils as bu
import spec/[crypto, datatypes, network, digest], ssz

const
  InspectorName* = "Beacon-Chain Network Inspector"
  InspectorMajor*: int = 0
  InspectorMinor*: int = 0
  InspectorPatch*: int = 2
  InspectorVersion* = $InspectorMajor & "." & $InspectorMinor & "." &
                      $InspectorPatch
  InspectorIdent* = "Inspector/$1 ($2/$3)" % [InspectorVersion,
                                              hostCPU, hostOS]
  InspectorCopyright* = "Copyright(C) 2019" &
                        " Status Research & Development GmbH"
  InspectorHeader* = InspectorName & ", Version " & InspectorVersion &
                     " [" & hostOS & ": " & hostCPU & "]\r\n" &
                     InspectorCopyright & "\r\n"

type
  TopicFilter* {.pure.} = enum
    Blocks, Attestations, Exits, ProposerSlashing, AttesterSlashings

  StartUpCommand* {.pure.} = enum
    noCommand

  InspectorConf* = object
    logLevel* {.
      defaultValue: LogLevel.TRACE
      desc: "Sets the inspector's verbosity log level"
      abbr: "v"
      name: "verbosity" }: LogLevel

    fullPeerId* {.
      defaultValue: false
      desc: "Sets the inspector full PeerID output"
      abbr: "p"
      name: "fullpeerid" }: bool

    floodSub* {.
      defaultValue: true
      desc: "Sets inspector engine to FloodSub"
      abbr: "f"
      name: "floodsub" }: bool

    gossipSub* {.
      defaultValue: false
      desc: "Sets inspector engine to GossipSub"
      abbr: "g"
      name: "gossipsub" }: bool

    signFlag* {.
      defaultValue: false
      desc: "Sets the inspector's to send/verify signatures in pubsub messages"
      abbr: "s"
      name: "sign" }: bool

    topics* {.
      desc: "Sets monitored topics, where `*` - all, " &
            "[a]ttestations, [b]locks, [e]xits, " &
            "[ps]roposer slashings, [as]ttester slashings"
      abbr: "t"
      name: "topics" }: seq[string]

    customTopics* {.
      desc: "Sets custom monitored topics"
      abbr: "c"
      name: "custom" }: seq[string]

    bootstrapFile* {.
      defaultValue: ""
      desc: "Specifies file which holds bootstrap nodes multiaddresses " &
            "delimeted by CRLF"
      abbr: "l"
      name: "bootfile" }: string

    bootstrapNodes* {.
      desc: "Specifies one or more bootstrap nodes" &
            " to use when connecting to the network"
      abbr: "b"
      name: "bootnodes" }: seq[string]

    decode* {.
      desc: "Try to decode message using SSZ"
      abbr: "d"
      defaultValue: false }: bool

proc getTopic(filter: TopicFilter): string {.inline.} =
  case filter
  of TopicFilter.Blocks:
    topicBeaconBlocks
  of TopicFilter.Attestations:
    topicAttestations
  of TopicFilter.Exits:
    topicVoluntaryExits
  of TopicFilter.ProposerSlashing:
    topicProposerSlashings
  of TopicFilter.AttesterSlashings:
    topicAttesterSlashings

proc getPeerId(peer: PeerID, conf: InspectorConf): string {.inline.} =
  if conf.fullPeerId:
    result = peer.pretty()
  else:
    result = $peer

proc loadBootFile(name: string): seq[string] =
  try:
    result = readFile(name).splitLines()
  except:
    discard

proc run(conf: InspectorConf) {.async.} =
  var
    bootnodes: seq[string]
    api: DaemonApi
    identity: PeerInfo
    pubsubPeers: Table[PeerID, PeerInfo]
    peerQueue: AsyncQueue[PeerID]
    subs: seq[tuple[ticket: PubsubTicket, future: Future[void]]]
    topics: set[TopicFilter] = {}

  pubsubPeers = initTable[PeerID, PeerInfo]()
  peerQueue = newAsyncQueue[PeerID]()

  proc dumpPeers(api: DaemonAPI) {.async.} =
    while true:
      var peers = await api.listPeers()
      info "Connected peers information", peers_connected = len(peers)
      for item in peers:
        info "Connected peer", peer = getPeerId(item.peer, conf),
                               addresses = item.addresses
      for key, value in pubsubPeers.pairs():
        info "Pubsub peer", peer = getPeerId(value.peer, conf),
                            addresses = value.addresses
      await sleepAsync(10.seconds)

  proc resolvePeers(api: DaemonAPI) {.async.} =
    var counter = 0
    while true:
      var peer = await peerQueue.popFirst()
      var info = await api.dhtFindPeer(peer)
      inc(counter)
      info "Peer resolved", peer = getPeerId(peer, conf),
                            addresses = info.addresses, count = counter
      pubsubPeers[peer] = info

  proc pubsubLogger(api: DaemonAPI,
                    ticket: PubsubTicket,
                    message: PubSubMessage): Future[bool] {.async.} =
    # We must return ``false`` only if we are not going to continue monitoring
    # of specific topic.
    var sig = if len(message.signature.data) > 0:
                $message.signature
              else:
                "<no signature>"
    var key = if len(message.signature.data) > 0:
                $message.key
              else:
                "<no public key>"

    var pinfo = pubsubPeers.getOrDefault(message.peer)
    if len(pinfo.peer) == 0:
      pubsubPeers[message.peer] = PeerInfo(peer: message.peer)
      peerQueue.addLastNoWait(message.peer)

    info "Received message", peerID = getPeerId(message.peer, conf),
                             size = len(message.data),
                             topic = ticket.topic,
                             seqno = bu.toHex(message.seqno),
                             signature = sig,
                             pubkey = key,
                             mtopics = $message.topics,
                             message = bu.toHex(message.data),
                             zpeers = len(pubsubPeers)

    if conf.decode:
      try:
        if ticket.topic.startsWith(topicBeaconBlocks):
          info "SignedBeaconBlock", msg = SSZ.decode(message.data, SignedBeaconBlock)
        elif ticket.topic.startsWith(topicAttestations):
          info "Attestation", msg = SSZ.decode(message.data, Attestation)
        elif ticket.topic.startsWith(topicVoluntaryExits):
          info "SignedVoluntaryExit", msg = SSZ.decode(message.data, SignedVoluntaryExit)
        elif ticket.topic.startsWith(topicProposerSlashings):
          info "ProposerSlashing", msg = SSZ.decode(message.data, ProposerSlashing)
        elif ticket.topic.startsWith(topicAttesterSlashings):
          info "AttesterSlashing", msg = SSZ.decode(message.data, AttesterSlashing)
      except CatchableError as exc:
        info "Unable to decode message", msg = exc.msg

    result = true

  if len(conf.topics) > 0:
    for item in conf.topics:
      let lcitem = item.toLowerAscii()

      if lcitem == "*":
        topics.incl({TopicFilter.Blocks, TopicFilter.Attestations,
                     TopicFilter.Exits, TopicFilter.ProposerSlashing,
                     TopicFilter.AttesterSlashings})
        break
      elif lcitem == "a":
        topics.incl(TopicFilter.Attestations)
      elif lcitem == "b":
        topics.incl(TopicFilter.Blocks)
      elif lcitem == "e":
        topics.incl(TopicFilter.Exits)
      elif lcitem == "ps":
        topics.incl(TopicFilter.ProposerSlashing)
      elif lcitem == "as":
        topics.incl(TopicFilter.AttesterSlashings)
      else:
        discard
  else:
    topics.incl({TopicFilter.Blocks, TopicFilter.Attestations,
                 TopicFilter.Exits, TopicFilter.ProposerSlashing,
                 TopicFilter.AttesterSlashings})

  if len(conf.bootstrapFile) > 0:
    info "Loading bootstrap nodes from file", filename = conf.bootstrapFile
    var nodes = loadBootFile(conf.bootstrapFile)
    for nodeString in nodes:
      try:
        var ma = MultiAddress.init(nodeString)
        if not(IPFS.match(ma)):
          warn "Incorrect bootnode address", address = nodeString
        else:
          bootnodes.add($ma)
      except:
        warn "Bootnode address is not valid MultiAddress", address = nodeString

  for nodeString in conf.bootstrapNodes:
    try:
      var ma = MultiAddress.init(nodeString)
      if not(IPFS.match(ma)):
        warn "Incorrect bootnode address", address = nodeString
      else:
        bootnodes.add($ma)
    except:
      warn "Bootnode address is not valid MultiAddress", address = nodeString

  if len(bootnodes) == 0:
    error "Not enough bootnodes to establish connection with network"
    quit(1)

  info InspectorIdent & " starting", bootnodes = bootnodes,
                                     topic_filters = topics

  var flags = {DHTClient, PSNoSign, WaitBootstrap}
  if conf.signFlag:
    flags.excl(PSNoSign)

  if conf.gossipSub:
    flags.incl(PSGossipSub)
  else:
    flags.incl(PSFloodSub)

  try:
    api = await newDaemonApi(flags, bootstrapNodes = bootnodes,
                             peersRequired = 1)
    identity = await api.identity()
    info InspectorIdent & " started", peerID = getPeerId(identity.peer, conf),
                                      bound = identity.addresses,
                                      options = flags
  except CatchableError as e:
    error "Could not initialize p2pd daemon",
          exception = e.msg
    quit(1)

  try:
    for filter in topics:
      let topic = getTopic(filter)
      let t = await api.pubsubSubscribe(topic, pubsubLogger)
      info "Subscribed to topic", topic = topic
      subs.add((ticket: t, future: t.transp.join()))
    for filter in conf.customTopics:
      let t = await api.pubsubSubscribe(filter, pubsubLogger)
      info "Subscribed to custom topic", topic = filter
      subs.add((ticket: t, future: t.transp.join()))
  except CatchableError as e:
    error "Could not subscribe to topics", exception = e.msg
    quit(1)

  # Starting DHT resolver task
  asyncCheck resolvePeers(api)
  # Starting peer dumper task
  asyncCheck dumpPeers(api)

  var futures = newSeq[Future[void]]()
  var delindex = 0
  while true:
    if len(subs) == 0:
      break
    futures.setLen(0)
    for item in subs:
      futures.add(item.future)
    var fut = await one(futures)
    for i in 0 ..< len(subs):
      if subs[i].future == fut:
        delindex = i
        break
    error "Subscription lost", topic = subs[delindex].ticket.topic
    subs.delete(delindex)

when isMainModule:
  echo InspectorHeader
  var conf = InspectorConf.load(version = InspectorVersion)
  waitFor run(conf)
