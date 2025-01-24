# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

type
  DatabaseDefect* = object of Defect
  SlashingDefect* = object of Defect
  ClearanceDefect* = object of Defect
  StrictDefect* = object of Defect
  NetworkDefect* = object of Defect
  DagDefect* = object of Defect
  KeystoreDefect* = object of Defect
  ProcessorDefect* = object of Defect
  DiscoveryDefect* = object of Defect
  ChainListDefect* = object of Defect
  OverseerDefect* = object of Defect

template raiseDatabaseDefect*(message: string) =
  raise (ref DatabaseDefect)(msg: message)

template raiseSlashingDefect*(message: string) =
  raise (ref SlashingDefect)(msg: message)

template raiseClearanceDefect*(message: string) =
  raise (ref ClearanceDefect)(msg: message)

template raiseStrictDefect*(message: string) =
  raise (ref StrictDefect)(msg: message)

template raiseDagDefect*(message: string) =
  raise (ref DagDefect)(msg: message)

template raiseKeystoreDefect*(message: string) =
  raise (ref KeystoreDefect)(msg: message)

template raiseProcessorDefect*(message: string) =
  raise (ref ProcessorDefect)(msg: message)

template raiseDiscoveryDefect*(message: string) =
  raise (ref DiscoveryDefect)(msg: message)

template raiseChainListDefect*(message: string) =
  raise (ref ChainListDefect)(msg: message)

template raiseOverseerDefect*(message: string) =
  raise (ref OverseerDefect)(msg: message)
