# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Temporary dumping ground for extra types and helpers that could make it into
# the spec potentially

import
  ./spec/[crypto, digest]

type
  InitialValidator* = object
    ## Eth1 validator registration contract output
    pubkey*: ValidatorPubKey
    deposit_size*: uint64
    proof_of_possession*: seq[byte]
    withdrawal_credentials*: Eth2Digest
    randao_commitment*: Eth2Digest
