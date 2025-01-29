# beacon_chain
# Copyright (c) 2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

type
  ExitProcessDefect* = object of Defect
    exitCode*: int8

  SuccessDefect* = object of ExitProcessDefect
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
  MetadataDefect* = object of ExitProcessDefect
  LogDefect* = object of ExitProcessDefect
  ConfigDefect* = object of ExitProcessDefect
  KeymanagerDefect* = object of ExitProcessDefect

  DepositsDefect* = object of ExitProcessDefect
  TrustedSyncDefect* = object of ExitProcessDefect
  WalletsDefect* = object of ExitProcessDefect
  BeaconNodeDefect* = object of ExitProcessDefect
  RecordDefect* = object of ExitProcessDefect
  Web3CmdDefect* = object of ExitProcessDefect
  SlashInterDefect* = object of ExitProcessDefect

  ValidatorClientDefect* = object of ExitProcessDefect
  LightClientDefect* = object of ExitProcessDefect

template declareExitHelpers(defect, code: untyped): untyped =
  template `raise defect`*() =
    raise (ref defect)(exitCode: code, msg: "")
  template `raise defect`*(message: string) =
    raise (ref defect)(exitCode: code, msg: message)

# Submodules exits
declareExitHelpers(SuccessDefect, 0)
declareExitHelpers(DatabaseDefect, 12)
declareExitHelpers(SlashingDefect, 13)
declareExitHelpers(NetworkDefect, 14)
declareExitHelpers(ClearanceDefect, 15)
declareExitHelpers(StrictDefect, 16)
declareExitHelpers(DagDefect, 17)
declareExitHelpers(KeystoreDefect, 18)
declareExitHelpers(ProcessorDefect, 19)
declareExitHelpers(DiscoveryDefect, 20)
declareExitHelpers(ChainListDefect, 21)
declareExitHelpers(OverseerDefect, 22)
declareExitHelpers(LogDefect, 23)
declareExitHelpers(ConfigDefect, 24)
declareExitHelpers(KeymanagerDefect, 25)
declareExitHelpers(MetadataDefect, 26)
# Modules exits
declareExitHelpers(DepositsDefect, 30)
declareExitHelpers(TrustedSyncDefect, 31)
declareExitHelpers(WalletsDefect, 32)
declareExitHelpers(BeaconNodeDefect, 33)
declareExitHelpers(RecordDefect, 34)
declareExitHelpers(Web3CmdDefect, 35)
declareExitHelpers(SlashInterDefect, 36)
declareExitHelpers(ValidatorClientDefect, 37)
declareExitHelpers(LightClientDefect, 38)

template withDefectsHandlers*(pbody, fbody: untyped) =
  try:
    pbody
  except ExitProcessDefect as exc:
    # This defects are already logged, so we just quit.
    quit(exc.exitCode)
  finally:
    fbody

template withDefectsHandlers*(pbody: untyped) =
  try:
    pbody
  except ExitProcessDefect as exc:
    # This defects are already logged, so we just quit.
    quit(exc.exitCode)
