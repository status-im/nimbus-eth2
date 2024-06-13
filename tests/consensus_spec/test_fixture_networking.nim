# beacon_chain
# Copyright (c) 2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  std/[json, streams],
  yaml,
  kzg4844/kzg_ex,
  stint,
  chronicles,
  eth/p2p/discoveryv5/[node],
  stew/[byteutils, results],
  ../../beacon_chain/spec/eip7594_helpers,
  ../testutil,
  ./fixtures_utils, ./os_ops

from std/sequtils import anyIt, mapIt, toSeq
from std/strutils import rsplit

func toUInt64(s: SomeInteger): Opt[uint64] =
  if s < 0:
    return Opt.none uint64
  try:
    Opt.some uint64(s)
  except ValueError:
    Opt.none uint64

func fromHex[N: static int](s: string): Opt[array[N, byte]] =
  if s.len != 2*(N+1):
    # 0x prefix
    return Opt.none array[N, byte]

  try:
    Opt.some fromHex(array[N, byte], s)
  except ValueError:
    Opt.none array[N, byte]

proc runGetCustodyColumns(suiteName, path: string) =
  let relativePathComponent = path.relativeTestPathComponent()
  test "Networking - Get Custody Columns - " & relativePathComponent:
    type TestMetaYaml = object
      node_id: string
      custody_subnet_count: uint64
      result: Option[seq[uint64]]
    let
      meta = block:
        var s = openFileStream(path/"meta.yaml")
        defer: close(s)
        var res: TestMetaYaml
        yaml.load(s, res)
        res
      node_id = UInt256.fromDecimal(meta.node_id)
      custody_subnet_count = toUInt64(meta.custody_subnet_count)
      reslt = (meta.result.get).mapIt(uint64(it))

    if custody_subnet_count.isNone:
      check meta.result.isNone
    else:
      let columns = get_custody_columns(node_id, custody_subnet_count.get)
      if columns.isErr:
        check meta.result.isNone
      else:
        var count = 0
        for column in columns.get:
          check column == uint64(reslt[count])
          count = count + 1

suite "EF - EIP7594 - Networking" & preset():
  const presetPath = SszTestsDir/const_preset
  let basePath =
    presetPath/"eip7594"/"networking"/"get_custody_columns"/"pyspec_tests"
  for kind, path in walkDir(basePath, relative = true, checkDir = true):
    runGetCustodyColumns(suiteName, basePath/path)