# beacon_chain
# Copyright (c) 2022 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# https://notes.ethereum.org/@9AeMAlpyQYaAAyuj47BzRw/rkwW3ceVY
# Monitor traffic: socat -v TCP-LISTEN:9550,fork TCP-CONNECT:127.0.0.1:8550

import
  std/options,
  stew/results,
  chronos,
  ../beacon_chain/eth1/eth1_monitor

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

from std/os import paramCount, paramStr
from nimcrypto/utils import fromHex
from web3/engine_api_types import PayloadExecutionStatus
from ../beacon_chain/networking/network_metadata import Eth1Network
from ../beacon_chain/spec/datatypes/base import ZERO_HASH
from ../beacon_chain/spec/presets import Eth1Address, defaultRuntimeConfig

# TODO factor this out and have a version with the result of the JWT secret
# slurp for testing purposes
proc readJwtSecret(jwtSecretFile: string): Result[seq[byte], cstring] =
  # https://github.com/ethereum/execution-apis/blob/v1.0.0-beta.1/src/engine/authentication.md#key-distribution
  # If such a parameter is given, but the file cannot be read, or does not
  # contain a hex-encoded key of 256 bits, the client should treat this as an
  # error: either abort the startup, or show error and continue without
  # exposing the authenticated port.
  const MIN_SECRET_LEN = 32

  try:
    let lines = readLines(jwtSecretFile, 1)
    if lines.len > 0:
      # Secret JWT key is parsed in constant time using nimcrypto:
      # https://github.com/cheatfate/nimcrypto/pull/44
      let secret = utils.fromHex(lines[0])
      if secret.len >= MIN_SECRET_LEN:
        ok(secret)
      else:
        err("JWT secret not at least 256 bits")
    else:
      err("JWT secret file empty")
  except IOError as exc:
    err("JWT secret file could not be read from")

proc run() {.async.} =
  if paramCount() < 2:
    echo "args are: web3url jwtsecretfilename"

  let
    eth1Monitor = Eth1Monitor.init(
      defaultRuntimeConfig, db = nil, nil, @[paramStr(1)],
      none(DepositTreeSnapshot), none(Eth1Network), false,
      some readJwtSecret(paramStr(2)).get)

  await eth1Monitor.ensureDataProvider()
  try:
    await eth1Monitor.exchangeTransitionConfiguration()
  except ValueError as exc:
    # Expected, since nothing here sets up the Nimbus TTD correctly
    echo "exchangeTransitionConfiguration ValueError: " & exc.msg
    echo "Invalid TTD errors are fine in this context"

waitFor run()
