# beacon_chain
# Copyright (c) 2018-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [], gcsafe.}

import
  std/typetraits,
  ssz_serialization/types,
  ../../beacon_chain/spec/datatypes/base
  # digest is necessary for them to be printed as hex

export base.`==`

# ---------------------------------------------------------------------

# This tool inspects and compare 2 instances of a type recursively
# highlighting the differences

func reportDiffImpl[T](x, y: T, xStr, yStr: string) =
  when T is HashList | HashArray | HashSeq:
    # TODO  resolve trouble with overloaded `[]` template
    discard
  elif T is BitArray:
    # TODO it doesn't have `low` or `high`, even as distinctBase
    discard
  elif T is SomeNumber | bool | char | enum | string |
      ValidatorSig | ValidatorPubKey | UInt256:
    doAssert(
      x == y,
      "\nDiff: " & xStr & " = " & $x & "\n" &
      "and   " & yStr & " = " & $y & "\n"
    )
  elif T is List | seq | array:
    doAssert(
      distinctBase(x).len == distinctBase(y).len,
      "\nDiff: " & xStr & ".len = " & $distinctBase(x).len & "\n" &
      "and   " & yStr & ".len = " & $distinctBase(y).len & "\n"
    )
    for idx in distinctBase(x).low .. distinctBase(x).high:
      doAssert(
        distinctBase(x)[idx] == distinctBase(y)[idx],
        "\nDiff: " & xStr & "[" & $idx & "] = " & $distinctBase(x)[idx] & "\n" &
        "and   " & yStr & "[" & $idx & "] = " & $distinctBase(y)[idx] & "\n"
      )
  elif T is ref:
    reportDiffImpl(x[], y[], xStr, yStr)
  elif T is distinct:
    reportDiffImpl(distinctBase(x), distinctBase(y), xStr, yStr)
  elif T is object:
    for name, xField, yField in fieldPairs(x, y):
      reportDiffImpl(xField, yField, xStr & "." & name, yStr & "." & name)
  else:
    {.error: "Unsupported type: " & $T.}

func reportDiff*[T](x, y: T) =
  reportDiffImpl(x, y, "x", "y")
