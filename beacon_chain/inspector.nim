# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.
import strutils, times, os
import confutils, chronicles, chronos, libp2p/daemon/daemonapi,
       libp2p/multiaddress
import stew/byteutils as bu
import spec/[datatypes, network]

const
  InspectorName* = "Beacon-Chain Network Inspector"
  InspectorMajor*: int = 0
  InspectorMinor*: int = 0
  InspectorPatch*: int = 1
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
    logLevel* {.desc: "Sets the inspector's verbosity log level",
                longform: "verbosity", shortform: "v",
                defaultValue: LogLevel.TRACE.}: LogLevel
    fullPeerId* {.desc: "Sets the inspector full PeerID output",
                  longform: "fullpeerid", shortform: "pid",
                  defaultValue: false.}: bool
    topics* {.desc: "Sets monitored topics, where `*` - all, " &
                    "[a]ttestations, [b]locks, [e]xits, " &
                    "[ps]roposer slashings, [as]ttester slashings",
              longform: "topics", shortform: "t".}: seq[string]
    customTopics* {.desc: "Sets custom monitored topics",
                    longform: "custom", shortform: "c".}: seq[string]
    bootstrapFile* {.
      desc: "Specifies file which holds bootstrap nodes multiaddresses " &
            "delimeted by CRLF",
      longform: "bootfile", shortform: "bf", defaultValue: "".}: string
    bootstrapNodes* {.
      desc: "Specifies one or more bootstrap nodes" &
            " to use when connecting to the network",
      longform: "bootnodes", shortform: "b".}: seq[string]


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
    subs: seq[tuple[ticket: PubsubTicket, future: Future[void]]]
    topics: set[TopicFilter] = {}

  proc pubsubLogger(api: DaemonAPI,
                    ticket: PubsubTicket,
                    message: PubSubMessage): Future[bool] {.async.} =
    # We must return ``false`` only if we are not going to continue monitoring
    # of specific topic.
    info "Received message", peerID = getPeerId(message.peer, conf),
                             size = len(message.data),
                             topic = ticket.topic,
                             seqno = bu.toHex(message.seqno),
                             signature = $message.signature,
                             pubkey = $message.key,
                             mtopics = $message.topics,
                             message = bu.toHex(message.data)
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

  var flags = {DHTClient, PSGossipSub, WaitBootstrap}
  try:
    api = await newDaemonApi(flags, bootstrapNodes = bootnodes,
                             peersRequired = 1)
    var identity = await api.identity()
    info InspectorIdent & " started", peerID = getPeerId(identity.peer, conf),
                                      bound = identity.addresses
  except:
    error "Could not initialize p2pd daemon",
          exception = getCurrentExceptionMsg()
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
  except:
    error "Could not subscribe to topics", exception = getCurrentExceptionMsg()
    quit(1)

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
