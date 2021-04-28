# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [Defect].}

import
  # Standard library
  os, strutils, tables,

  # Local modules
  ./spec/[digest, crypto],
  ./validators/keystore_management

{.pop.} # TODO moduletests exceptions

programMain:
  var validators: Table[ValidatorPubKey, ValidatorPrivKey]
  # load and send all public keys so the BN knows for which ones to ping us
  doAssert paramCount() == 2
  for curr in validatorKeysFromDirs(paramStr(1), paramStr(2)):
    validators[curr.toPubKey] = curr
    echo curr.toPubKey
  echo "end"

  # simple format: `<pubkey> <eth2digest_to_sign>` => `<signature>`
  while true:
    let args = stdin.readLine.split(" ")
    doAssert args.len == 2

    let privKey = validators[ValidatorPubKey.fromHex(args[0]).get()]

    echo blsSign(privKey, Eth2Digest.fromHex(args[1]).data).toValidatorSig()
