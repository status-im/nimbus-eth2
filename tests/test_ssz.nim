# beacon_chain
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  unittest, sequtils, options,
  stint, nimcrypto, eth/common, blscurve, serialization/testing/generic_suite,
  ../beacon_chain/spec/[datatypes, digest],
  ../beacon_chain/ssz, ../beacon_chain/ssz/navigator

type
  SomeEnum = enum
    A, B, C

  Simple = object
    flag: bool
    # count: StUint[256]
    # ignored {.dontSerialize.}: string
    # data: array[256, bool]

template reject(stmt) =
  assert(not compiles(stmt))

static:
  assert isFixedSize(bool) == true

  assert fixedPortionSize(array[10, bool]) == 10
  assert fixedPortionSize(array[SomeEnum, uint64]) == 24
  assert fixedPortionSize(array[3..5, string]) == 12

  assert fixedPortionSize(string) == 4
  assert fixedPortionSize(seq[bool]) == 4
  assert fixedPortionSize(seq[string]) == 4

  assert isFixedSize(array[20, bool]) == true
  assert isFixedSize(Simple) == true
  assert isFixedSize(string) == false
  assert isFixedSize(seq[bool]) == false
  assert isFixedSize(seq[string]) == false

  reject fixedPortionSize(int)

type
  ObjWithFields = object
    f0: uint8
    f1: uint32
    f2: EthAddress
    f3: MDigest[256]
    f4: seq[byte]
    f5: ValidatorIndex

static:
  assert fixedPortionSize(ObjWithFields) == 1 + 4 + sizeof(EthAddress) + (256 div 8) + 4 + 8

executeRoundTripTests SSZ

type
  Foo = object
    bar: Bar

  Bar = object
    b: string
    baz: Baz

  Baz = object
    i: uint64

suite "SSZ Navigation":
  test "simple object fields":
    var foo = Foo(bar: Bar(b: "bar", baz: Baz(i: 10'u64)))
    let encoded = SSZ.encode(foo)

    check SSZ.decode(encoded, Foo) == foo

    let mountedFoo = sszMount(encoded, Foo)
    check mountedFoo.bar.b == "bar"

    let mountedBar = mountedFoo.bar
    check mountedBar.baz.i == 10'u64

