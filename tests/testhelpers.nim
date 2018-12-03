# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  ../beacon_chain/extras,
  ../beacon_chain/spec/[crypto, datatypes]

func makeValidatorPubKey(n: int): ValidatorPubKey =
  result.point.x.a.g[0] = n

func makeInitialValidators*(n = EPOCH_LENGTH): seq[InitialValidator] =
  for i in 0..<n:
    result.add InitialValidator(
      pubkey: makeValidatorPubKey(i)
    )
