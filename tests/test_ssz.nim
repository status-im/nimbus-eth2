# beacon_chain
# Copyright (c) 2018-2021 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  std/[options],
  unittest2,
  nimcrypto/hash,
  json_serialization,
  ../beacon_chain/spec/datatypes/base,
  ../beacon_chain/ssz,
  ../beacon_chain/ssz/[navigator, dynamic_navigator]

type
  SomeEnum = enum
    A, B, C

  Simple = object
    flag: bool
    # ignored {.dontSerialize.}: string
    data: array[256, bool]
    data2: HashArray[256, bool]

  NonFixed = object
    data: HashList[uint64, 1024]

template reject(stmt) =
  doAssert(not compiles(stmt))

static:
  doAssert isFixedSize(bool) == true

  doAssert fixedPortionSize(array[10, bool]) == 10
  doAssert fixedPortionSize(array[SomeEnum, uint64]) == 24
  doAssert fixedPortionSize(array[3..5, List[byte, 256]]) == 12

  doAssert isFixedSize(array[20, bool]) == true
  doAssert isFixedSize(Simple) == true
  doAssert isFixedSize(List[bool, 128]) == false

  doAssert isFixedSize(NonFixed) == false

  reject fixedPortionSize(int)

type
  ObjWithFields = object
    f0: uint8
    f1: uint32
    f2: array[20, byte]
    f3: MDigest[256]
    f4: seq[byte]
    f5: ValidatorIndex

static:
  doAssert fixedPortionSize(ObjWithFields) ==
    1 + 4 + sizeof(array[20, byte]) + (256 div 8) + 4 + 8

type
  Foo = object
    bar: Bar

  BarList = List[uint64, 128]

  Bar = object
    b: BarList
    baz: Baz

  Baz = object
    i: uint64

proc toDigest[N: static int](x: array[N, byte]): Eth2Digest =
  result.data[0 .. N-1] = x

suite "SSZ navigator":
  test "simple object fields":
    var foo = Foo(bar: Bar(b: BarList @[1'u64, 2, 3], baz: Baz(i: 10'u64)))
    let encoded = SSZ.encode(foo)

    check SSZ.decode(encoded, Foo) == foo

    let mountedFoo = sszMount(encoded, Foo)
    check mountedFoo.bar.b[] == BarList @[1'u64, 2, 3]

    let mountedBar = mountedFoo.bar
    check mountedBar.baz.i == 10'u64

  test "lists with max size":
    let a = [byte 0x01, 0x02, 0x03].toDigest
    let b = [byte 0x04, 0x05, 0x06].toDigest
    let c = [byte 0x07, 0x08, 0x09].toDigest

    var xx: List[uint64, 16]
    check:
      not xx.setLen(17)
      xx.setLen(16)

    var leaves = HashList[Eth2Digest, 1'i64 shl 3]()
    check:
      leaves.add a
      leaves.add b
      leaves.add c
    let root = hash_tree_root(leaves)
    check $root == "5248085b588fab1dd1e03f3cd62201602b12e6560665935964f46e805977e8c5"

    while leaves.len < 1 shl 3:
      check:
        leaves.add c
        hash_tree_root(leaves) == hash_tree_root(leaves.data)

    leaves = default(type leaves)

    while leaves.len < (1 shl 3) - 1:
      check:
        leaves.add c
        leaves.add c
        hash_tree_root(leaves) == hash_tree_root(leaves.data)

    leaves = default(type leaves)

    while leaves.len < (1 shl 3) - 2:
      check:
        leaves.add c
        leaves.add c
        leaves.add c
        hash_tree_root(leaves) == hash_tree_root(leaves.data)

    for i in 0 ..< leaves.data.len - 2:
      leaves[i] = a
      leaves[i + 1] = b
      leaves[i + 2] = c
      check hash_tree_root(leaves) == hash_tree_root(leaves.data)

    var leaves2 = HashList[Eth2Digest, 1'i64 shl 48]() # Large number!
    check:
      leaves2.add a
      leaves2.add b
      leaves2.add c
      hash_tree_root(leaves2) == hash_tree_root(leaves2.data)

    var leaves3 = HashList[Eth2Digest, 7]() # Non-power-of-2
    check:
      hash_tree_root(leaves3) == hash_tree_root(leaves3.data)
      leaves3.add a
      leaves3.add b
      leaves3.add c
      hash_tree_root(leaves3) == hash_tree_root(leaves3.data)

  test "basictype":
    var leaves = HashList[uint64, 1'i64 shl 3]()
    while leaves.len < leaves.maxLen:
      check:
        leaves.add leaves.lenu64
        hash_tree_root(leaves) == hash_tree_root(leaves.data)

suite "SSZ dynamic navigator":
  test "navigating fields":
    var fooOrig = Foo(bar: Bar(b: BarList @[1'u64, 2, 3], baz: Baz(i: 10'u64)))
    let fooEncoded = SSZ.encode(fooOrig)

    var navFoo = DynamicSszNavigator.init(fooEncoded, Foo)

    var navBar = navFoo.navigate("bar")
    check navBar.toJson(pretty = false) == """{"b":[1,2,3],"baz":{"i":10}}"""

    var navB = navBar.navigate("b")
    check navB.toJson(pretty = false) == "[1,2,3]"

    var navBaz = navBar.navigate("baz")
    var navI = navBaz.navigate("i")
    check navI.toJson == "10"

    expect KeyError:
      discard navBar.navigate("biz")

type
  Obj = object
    arr: array[8, Eth2Digest]

    li: List[Eth2Digest, 8]

  HashObj = object
    arr: HashArray[8, Eth2Digest]

    li: HashList[Eth2Digest, 8]

suite "hash":
  test "HashArray":
    var
      o = Obj()
      ho = HashObj()

    template both(body) =
      block:
        template it: auto {.inject.} = o
        body
      block:
        template it: auto {.inject.} = ho
        body

      let htro = hash_tree_root(o)
      let htrho = hash_tree_root(ho)

      check:
        o.arr == ho.arr.data
        o.li == ho.li.data
        htro == htrho

    both: it.arr[0].data[0] = byte 1

    both: check: it.li.add Eth2Digest()

    var y: HashArray[32, uint64]
    check: hash_tree_root(y) == hash_tree_root(y.data)
    for i in 0..<y.len:
      y[i] = 42'u64
      check: hash_tree_root(y) == hash_tree_root(y.data)

  test "HashList fixed":
    type MyList = HashList[uint64, 1024]
    var
      small, large: MyList

    let
      emptyBytes = SSZ.encode(small)
      emptyRoot = hash_tree_root(small)

    check: small.add(10'u64)

    for i in 0..<100:
      check: large.add(uint64(i))

    let
      sroot = hash_tree_root(small)
      lroot = hash_tree_root(large)

    check:
      sroot == hash_tree_root(small.data)
      lroot == hash_tree_root(large.data)

    var
      sbytes = SSZ.encode(small)
      lbytes = SSZ.encode(large)
      sloaded = SSZ.decode(sbytes, MyList)
      lloaded = SSZ.decode(lbytes, MyList)

    check:
      sroot == hash_tree_root(sloaded)
      lroot == hash_tree_root(lloaded)

    # Here we smoke test that the cache is reset correctly even when reading
    # into an existing instance - the instances are size-swapped so the reader
    # will have some more work to do
    readSszValue(sbytes, lloaded)
    readSszValue(lbytes, sloaded)

    check:
      lroot == hash_tree_root(sloaded)
      sroot == hash_tree_root(lloaded)

    readSszValue(emptyBytes, sloaded)
    check:
      emptyRoot == hash_tree_root(sloaded)

  test "HashList variable":
    type MyList = HashList[NonFixed, 1024]
    var
      small, large: MyList

    let
      emptyBytes = SSZ.encode(small)
      emptyRoot = hash_tree_root(small)

    check: small.add(NonFixed())

    for i in 0..<100:
      check: large.add(NonFixed())

    let
      sroot = hash_tree_root(small)
      lroot = hash_tree_root(large)

    check:
      sroot == hash_tree_root(small.data)
      lroot == hash_tree_root(large.data)

    var
      sbytes = SSZ.encode(small)
      lbytes = SSZ.encode(large)
      sloaded = SSZ.decode(sbytes, MyList)
      lloaded = SSZ.decode(lbytes, MyList)

    check:
      sroot == hash_tree_root(sloaded)
      lroot == hash_tree_root(lloaded)

    # Here we smoke test that the cache is reset correctly even when reading
    # into an existing instance - the instances are size-swapped so the reader
    # will have some more work to do
    readSszValue(sbytes, lloaded)
    readSszValue(lbytes, sloaded)

    check:
      lroot == hash_tree_root(sloaded)
      sroot == hash_tree_root(lloaded)

    readSszValue(emptyBytes, sloaded)
    check:
      emptyRoot == hash_tree_root(sloaded)
