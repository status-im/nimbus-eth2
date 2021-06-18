# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  std/[typetraits, sequtils, os, algorithm, math, sets, tables]

import
  chronos, chronicles, metrics,
  libp2p/[switch, peerinfo]

logScope:
  topics = "networking peer_balancer"

type
  PeerKicker* =
    proc (peerId: PeerID): Future[void] {.gcsafe.}

  PeerGroup* = ref object
    name*: string
    totalScore*: int
    lowPeers*: int
    peers: HashSet[PeerID]
    kicker: PeerKicker

  PeerBalancer* = ref object
    peerGroups*: seq[PeerGroup]
    maxPeers*: int

const
  #Can't be INT_MAX because that would overflow
  groupWithLowPeersScore = 1_000_000_000

proc sortPerScore(a, b: (PeerID, int)): int =
  system.cmp(a[1], b[1])

proc computeScores(balancer: PeerBalancer): OrderedTable[PeerID, int] =
  var scores = initOrderedTable[PeerID, int]()

  for group in balancer.peerGroups:
    let scorePerPeer =
      if group.peers.len <= group.lowPeers:
        groupWithLowPeersScore
      else:
        group.totalScore div group.peers.len

    for peer in group.peers:
      scores[peer] = scores.getOrDefault(peer) + scorePerPeer

  scores.sort(sortPerScore)

  return scores

proc trimConnections*(balancer: PeerBalancer) {.async.} =
  var scores = balancer.computeScores()

  trace "starting trimming", scores

  if scores.len <= balancer.maxPeers: return

  var toKick: int = scores.len - balancer.maxPeers

  for peerId in scores.keys:
    await balancer.peerGroups[0].kicker(peerId)
    dec toKick
    if toKick < 0: break

proc addGroup*(
  balancer: PeerBalancer,
  name: string,
  totalScore: int,
  kicker: PeerKicker,
  lowPeers = 0): PeerGroup =

  trace "new peer group", name, totalScore, lowPeers

  var group = PeerGroup(
    name: name,
    totalScore: totalScore,
    kicker: kicker,
    lowPeers: lowPeers)
  balancer.peerGroups.add(group)
  return group

proc addPeer*(group: PeerGroup, peer: PeerID) =
  group.peers.incl(peer)

proc removePeer*(group: PeerGroup, peer: PeerID) =
  group.peers.excl(peer)

proc removePeer*(balancer: PeerBalancer, peer: PeerId) =
  for group in balancer.peerGroups:
    group.removePeer(peer)

proc new*(T: typedesc[PeerBalancer], maxPeers: int): T =
  T(maxPeers: maxPeers)
