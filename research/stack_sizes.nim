# beacon_chain
# Copyright (c) 2020-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import ../beacon_chain/spec/datatypes/phase0

import std/[typetraits, strformat, strutils]

proc print(t: auto, n: string, indent: int) =
  echo fmt"{sizeof(t):>8}  {spaces(indent)}{n}: {typeof(t).name}"

  when t is object|tuple:
    for n, p in t.fieldPairs:
      print(p, n, indent + 1)

print((ref BeaconState)()[], "state", 0)

echo ""

print(SignedBeaconBlock(), "block", 0)

echo ""

print(Validator(), "validator", 0)

echo ""

print(Attestation(), "attestation", 0)
