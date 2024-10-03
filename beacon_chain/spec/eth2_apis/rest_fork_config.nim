# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/strutils,
  stew/[base10, byteutils],
  ../forks

from ./rest_types import VCRuntimeConfig

export forks, rest_types

type
  VCForkConfig* = object
    altairVersion*: Opt[Version]
    altairEpoch*: Epoch
    capellaVersion*: Opt[Version]
    capellaEpoch*: Epoch
    denebVersion*: Opt[Version]
    denebEpoch*: Epoch
    electraVersion*: Opt[Version]
    electraEpoch*: Epoch

func forkVersionConfigKey*(consensusFork: ConsensusFork): string =
  if consensusFork > ConsensusFork.Phase0:
    ($consensusFork).toUpperAscii() & "_FORK_VERSION"
  else:
    "GENESIS_FORK_VERSION"

func forkEpochConfigKey*(consensusFork: ConsensusFork): string =
  doAssert consensusFork > ConsensusFork.Phase0
  ($consensusFork).toUpperAscii() & "_FORK_EPOCH"

func getOrDefault*(info: VCRuntimeConfig, name: string,
                   default: uint64): uint64 =
  let numstr = info.getOrDefault(name, "missing")
  if numstr == "missing": return default
  Base10.decode(uint64, numstr).valueOr:
    return default

func getOrDefault*(info: VCRuntimeConfig, name: string, default: Epoch): Epoch =
  Epoch(info.getOrDefault(name, uint64(default)))

func getForkVersion(
    info: VCRuntimeConfig,
    consensusFork: ConsensusFork): Result[Opt[Version], string] =
  let key = consensusFork.forkVersionConfigKey()
  let stringValue = info.getOrDefault(key, "missing")
  if stringValue == "missing": return ok Opt.none(Version)
  var value: Version
  try:
    hexToByteArrayStrict(stringValue, distinctBase(value))
  except ValueError as exc:
    return err(key & " is invalid: " & exc.msg)
  ok Opt.some value

func getForkEpoch(info: VCRuntimeConfig, consensusFork: ConsensusFork): Epoch =
  if consensusFork > ConsensusFork.Phase0:
    let key = consensusFork.forkEpochConfigKey()
    info.getOrDefault(key, FAR_FUTURE_EPOCH)
  else:
    GENESIS_EPOCH

template toString(epoch: Epoch): string =
  Base10.toString(uint64(epoch))

func getConsensusForkConfig*(
    info: VCRuntimeConfig): Result[VCForkConfig, string] =
  ## This extracts all `_FORK_VERSION` and `_FORK_EPOCH` constants
  ## that are relevant for Validator Client operation.
  ##
  ## Note that the fork schedule (`/eth/v1/config/fork_schedule`) cannot be used
  ## because it does not indicate whether the forks refer to `ConsensusFork` or
  ## to a different fork sequence from an incompatible network (e.g., devnet)
  let
    res = VCForkConfig(
      altairVersion: ? info.getForkVersion(ConsensusFork.Altair),
      altairEpoch: info.getForkEpoch(ConsensusFork.Altair),
      capellaVersion: ? info.getForkVersion(ConsensusFork.Capella),
      capellaEpoch: info.getForkEpoch(ConsensusFork.Capella),
      denebVersion: ? info.getForkVersion(ConsensusFork.Deneb),
      denebEpoch: info.getForkEpoch(ConsensusFork.Deneb),
      electraVersion: ? info.getForkVersion(ConsensusFork.Electra),
      electraEpoch: info.getForkEpoch(ConsensusFork.Electra))

  if res.capellaEpoch < res.altairEpoch:
    return err(
      "Fork epochs are inconsistent, " & $ConsensusFork.Capella &
      " is scheduled at epoch " & res.capellaEpoch.toString() &
      " which is before prior fork epoch " & res.altairEpoch.toString())
  if res.denebEpoch < res.capellaEpoch:
    return err(
      "Fork epochs are inconsistent, " & $ConsensusFork.Deneb &
      " is scheduled at epoch " & res.denebEpoch.toString() &
      " which is before prior fork epoch " & res.capellaEpoch.toString())
  if res.electraEpoch < res.denebEpoch:
    return err(
      "Fork epochs are inconsistent, " & $ConsensusFork.Electra &
      " is scheduled at epoch " & res.electraEpoch.toString() &
      " which is before prior fork epoch " & res.denebEpoch.toString())

  if (res.capellaEpoch != FAR_FUTURE_EPOCH) and res.capellaVersion.isNone():
    return err(
      "Beacon node has scheduled " &
      ConsensusFork.Capella.forkEpochConfigKey() &
      " but does not report " &
      ConsensusFork.Capella.forkVersionConfigKey())
  if (res.denebEpoch != FAR_FUTURE_EPOCH) and res.denebVersion.isNone():
    return err(
      "Beacon node has scheduled " &
      ConsensusFork.Deneb.forkEpochConfigKey() &
      " but does not report " &
      ConsensusFork.Deneb.forkVersionConfigKey())
  if (res.electraEpoch != FAR_FUTURE_EPOCH) and res.electraVersion.isNone():
    return err(
      "Beacon node has scheduled " &
      ConsensusFork.Electra.forkEpochConfigKey() &
      " but does not report " &
      ConsensusFork.Electra.forkVersionConfigKey())

  ok(res)
