# beacon_chain
# Copyright (c) 2018-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/[sequtils, strutils, tables],
  stew/[base10, byteutils],
  ../forks

from ./rest_types import VCRuntimeConfig

export forks, tables, rest_types

type
  ForkConfigItem* = object
    version*: Version
    epoch*: Epoch

  VCForkConfig* = Table[ConsensusFork, ForkConfigItem]

func forkVersionConfigKey*(consensusFork: ConsensusFork): string =
  if consensusFork > ConsensusFork.Phase0:
    ($consensusFork).toUpperAscii() & "_FORK_VERSION"
  else:
    "GENESIS_FORK_VERSION"

func forkEpochConfigKey*(consensusFork: ConsensusFork): string =
  doAssert consensusFork > ConsensusFork.Phase0
  ($consensusFork).toUpperAscii() & "_FORK_EPOCH"

func getOrDefault*(info: VCRuntimeConfig, name: string,
                   defaultValue: uint64): uint64 =
  let numstr =
    try:
      info[name]
    except KeyError:
      return defaultValue
  Base10.decode(uint64, numstr).valueOr:
    return defaultValue

func getOrDefault*(info: VCRuntimeConfig, name: string, default: Epoch): Epoch =
  Epoch(info.getOrDefault(name, uint64(default)))

func getForkVersion(
    info: VCRuntimeConfig,
    consensusFork: ConsensusFork
): Result[Version, string] =
  let
    key = consensusFork.forkVersionConfigKey()
    stringValue =
      try:
        info[key]
      except KeyError:
        return err("Forks configuration missing value " & $consensusFork)
  var value: Version
  try:
    hexToByteArrayStrict(stringValue, distinctBase(value))
  except ValueError as exc:
    return err(key & " is invalid, reason " & exc.msg)
  ok(value)

func getForkEpoch(info: VCRuntimeConfig,
                  consensusFork: ConsensusFork): Result[Epoch, string] =
  if consensusFork > ConsensusFork.Phase0:
    let
      key = consensusFork.forkEpochConfigKey()
      stringValue =
        try:
          info[key]
        except KeyError:
          return err("Forks configuration missing value " & $consensusFork)
      numValue = Base10.decode(uint64, stringValue).valueOr:
        return err(key & " is invalid, reason " & $error)
    ok(Epoch(numValue))
  else:
    ok(GENESIS_EPOCH)

template toString(epoch: Epoch): string =
  Base10.toString(uint64(epoch))

func getConsensusForkConfig*(
    info: VCRuntimeConfig
): Result[VCForkConfig, string] =
  ## This extracts all `_FORK_VERSION` and `_FORK_EPOCH` constants
  var
    config: VCForkConfig
    presence: set[ConsensusFork]
  for fork in ConsensusFork:
    let
      forkVersion = ? info.getForkVersion(fork)
      forkEpoch = ? info.getForkEpoch(fork)
    config[fork] = ForkConfigItem(version: forkVersion, epoch: forkEpoch)
    presence.incl(fork)

  let forks = ConsensusFork.toSeq()
  if len(presence) != (int(high(ConsensusFork)) + 1):
    let missingForks = forks.filterIt(it notin presence)
    return err(
      "Some forks missing in configuration [" &
      missingForks.mapIt($it).join(", ") & "]")

  try:
    for index, fork in forks.pairs():
      if index > 0:
        if config[forks[index]].epoch < config[forks[index - 1]].epoch:
          return err(
            "Fork epochs are inconsistent, " & $forks[index] &
            " is scheduled at epoch " &
            config[forks[index]].epoch.toString() &
            " which is before prior fork epoch " &
            config[forks[index - 1]].epoch.toString())
  except KeyError:
    raiseAssert "Forks configuration is missing values"
  ok(config)
