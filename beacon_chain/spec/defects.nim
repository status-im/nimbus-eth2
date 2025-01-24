# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

type
  ExitProcessDefect* = object of Defect
    exitCode*: int16

  DatabaseDefect* = object of ExitProcessDefect
  SlashingDefect* = object of ExitProcessDefect
  NetworkDefect* = object of ExitProcessDefect
  ClearanceDefect* = object of ExitProcessDefect
  StrictDefect* = object of ExitProcessDefect
  DagDefect* = object of ExitProcessDefect
  KeystoreDefect* = object of ExitProcessDefect
  ProcessorDefect* = object of ExitProcessDefect
  DiscoveryDefect* = object of ExitProcessDefect
  ChainListDefect* = object of ExitProcessDefect
  OverseerDefect* = object of ExitProcessDefect

template raiseDatabaseDefect*(message: string) =
  raise (ref DatabaseDefect)(exitCode: 12, msg: message)

template raiseSlashingDefect*(message: string) =
  raise (ref SlashingDefect)(exitCode: 13, msg: message)

template raiseClearanceDefect*(message: string) =
  raise (ref ClearanceDefect)(exitCode: 14, msg: message)

template raiseStrictDefect*(message: string) =
  raise (ref StrictDefect)(exitCode: 15, msg: message)

template raiseDagDefect*(message: string) =
  raise (ref DagDefect)(exitCode: 16, msg: message)

template raiseKeystoreDefect*(message: string) =
  raise (ref KeystoreDefect)(exitCode: 17, msg: message)

template raiseProcessorDefect*(message: string) =
  raise (ref ProcessorDefect)(exitCode: 18, msg: message)

template raiseDiscoveryDefect*(message: string) =
  raise (ref DiscoveryDefect)(exitCode: 19, msg: message)

template raiseChainListDefect*(message: string) =
  raise (ref ChainListDefect)(exitCode: 20, msg: message)

template raiseOverseerDefect*(message: string) =
  raise (ref OverseerDefect)(exitCode: 21, msg: message)

template raiseNetworkDefect*(message: string) =
  raise (ref NetworkDefect)(exitCode: 22, msg: message)
