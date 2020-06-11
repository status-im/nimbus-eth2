# beacon_chain
# Copyright (c) 2018-2020 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# SSZ Serialization (simple serialize)
# See https://github.com/ethereum/eth2.0-specs/blob/master/specs/simple-serialize.md

{.push raises: [Defect].}

# TODO Many RVO bugs, careful
# https://github.com/nim-lang/Nim/issues/14470
# https://github.com/nim-lang/Nim/issues/14126

import
  ./ssz/[merkleization, ssz_serialization, types]

export
  merkleization, ssz_serialization, types
