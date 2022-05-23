# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import std/options
import stew/results

from std/strutils import split, splitLines, strip
from std/tables import Table, contains, `[]`, `[]=`
from web3/ethtypes import fromHex
from ".."/spec/crypto import ValidatorPubKey, fromHex, hash
from ".."/spec/presets import Eth1Address

{.push raises: [Defect].}

type
  FeeRecipientTable* = Table[ValidatorPubKey, Eth1Address]

func parseFeeRecipientList*(s: string): Result[FeeRecipientTable, cstring] =
  var feeRecipients: Table[ValidatorPubKey, Eth1Address]

  # Allow for trailing newlines, while (conservatively) disallowing interior
  # blank lines.
  for line in splitLines(s.strip(leading = false, trailing = true)):
    let parts = line.split(":", 1)
    if len(parts) < 2:
      return err("parseFeeRecipientList: invalid suggested fee recipient file format")

    let key =
      if parts[0] == "default":
        default(ValidatorPubKey)
      else:
        let pubkey = ValidatorPubKey.fromHex(parts[0])
        if pubkey.isErr():
          return err("parseFeeRecipientList: invalid validator public key")
        pubkey.get

    if key in feeRecipients:
      return err("parseFeeRecipientList: duplicate validator public key")

    try:
      # Initially, start somewhat stricter
      feeRecipients[key] = Eth1Address.fromHex(
        strip(parts[1], leading = true, trailing = false))
    except ValueError:
      return err("parseFeeRecipientList: invalid suggested fee recipient")

  ok(feeRecipients)

proc getFeeRecipientList*(filename: string):
    Result[Table[ValidatorPubKey, Eth1Address], cstring] =
  try:
    parseFeeRecipientList(readFile(filename))
  except IOError:
    err("getFeeValidatorList: couldn't read suggested fee validator file")

func getFeeRecipient*(
    suggestedFeeRecipient: Option[Eth1Address],
    suggestedFeeRecipients: FeeRecipientTable,
    pubkey: ValidatorPubKey):
    Eth1Address =
  const defaultKey = default(ValidatorPubKey)
  if pubkey in suggestedFeeRecipients:
    try:
      suggestedFeeRecipients[pubkey]
    except KeyError:
      raiseAssert "Already checked in if condition"
  elif defaultKey in suggestedFeeRecipients:
    try:
      suggestedFeeRecipients[defaultKey]
    except KeyError:
      raiseAssert "Already checked in if condition"
  elif suggestedFeeRecipient.isSome:
    suggestedFeeRecipient.get
  else:
    default(Eth1Address)
