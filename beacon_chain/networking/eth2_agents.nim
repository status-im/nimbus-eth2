# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import stew/base10
import std/tables
import libp2p/[multiaddress, multicodec, peerstore]

type
  Eth2Agent* {.pure.} = enum
    Unknown,
    Nimbus,
    Lighthouse,
    Prysm,
    Teku,
    Lodestar,
    Grandine

func `$`*(a: Eth2Agent): string =
  case a
  of Eth2Agent.Unknown:
    "unrecognized"
  of Eth2Agent.Nimbus:
    "nimbus"
  of Eth2Agent.Lighthouse:
    "lighthouse"
  of Eth2Agent.Prysm:
    "prysm"
  of Eth2Agent.Teku:
    "teku"
  of Eth2Agent.Lodestar:
    "lodestar"
  of Eth2Agent.Grandine:
    "grandine"

const
  # Lighthouse errors could be found here
  # https://github.com/sigp/lighthouse/blob/stable/beacon_node/lighthouse_network/src/rpc/methods.rs
  LighthouseErrors = [
    (128'u64, "Unable to verify network"),
    (129'u64, "The node has too many connected peers"),
    (250'u64, "Peer score is too low"),
    (251'u64, "The peer is banned"),
    (252'u64, "The IP address the peer is using is banned"),
  ].toTable()

  # Prysm errors could be found here
  # https://github.com/prysmaticlabs/prysm/blob/develop/beacon-chain/p2p/types/rpc_goodbye_codes.go
  PrysmErrors = [
    (128'u64, "Unable to verify network"),
    (129'u64, "The node has too many connected peers"),
    (250'u64, "Peer score is too low"),
    (251'u64, "The peer is banned")
  ].toTable()

  # Lodestar errors could be found here
  # https://github.com/ChainSafe/lodestar/blob/unstable/packages/beacon-node/src/constants/network.ts
  LodestarErrors = [
    (128'u64, "Unable to verify network"),
    (129'u64, "The node has too many connected peers"),
    (250'u64, "Peer score is too low"),
    (251'u64, "The peer is banned")
  ].toTable()

  # Teku errors could be found here
  # https://github.com/Consensys/teku/blob/master/ethereum/spec/src/main/java/tech/pegasys/teku/spec/datastructures/networking/libp2p/rpc/GoodbyeMessage.java
  TekuErrors = [
    (128'u64, "Unable to verify network"),
    (129'u64, "The node has too many connected peers"),
    (130'u64, "Too many requests from the peer")
  ].toTable()

  # Nimbus errors could be found here
  # https://github.com/status-im/nimbus-eth2/blob/unstable/beacon_chain/networking/eth2_network.nim
  NimbusErrors = [
    (237'u64, "Peer score is too low")
  ].toTable()

  # Grandine errors could be found here
  # https://github.com/grandinetech/eth2_libp2p/blob/main/src/rpc/methods.rs
  GrandineErrors = [
    (128'u64, "Unable to verify network"),
    (129'u64, "The node has too many connected peers"),
    (250'u64, "Peer score is too low"),
    (251'u64, "The peer is banned"),
    (252'u64, "The IP address the peer is using is banned"),
  ].toTable()

func disconnectReasonName*(a: Eth2Agent, code: uint64): string =
  if code < 128'u64:
    case code
    of 1'u64:
      "Client shutdown (1)"
    of 2'u64:
      "Irrelevant network (2)"
    of 3'u64:
      "Fault or error (3)"
    else:
      let
        scode = " (" & Base10.toString(code) & ")"
        defaultMessage = "Disconnected"

      defaultMessage & scode
  else:
    let
      scode = " (" & Base10.toString(code) & ")"
      defaultMessage = "Disconnected"

    case a
    of Eth2Agent.Unknown:
      "Disconnected" & scode
    of Eth2Agent.Nimbus:
      NimbusErrors.getOrDefault(code, defaultMessage) & scode
    of Eth2Agent.Lighthouse:
      LighthouseErrors.getOrDefault(code, defaultMessage) & scode
    of Eth2Agent.Prysm:
      PrysmErrors.getOrDefault(code, defaultMessage) & scode
    of Eth2Agent.Teku:
      TekuErrors.getOrDefault(code, defaultMessage) & scode
    of Eth2Agent.Lodestar:
      LodestarErrors.getOrDefault(code, defaultMessage) & scode
    of Eth2Agent.Grandine:
      GrandineErrors.getOrDefault(code, defaultMessage) & scode
