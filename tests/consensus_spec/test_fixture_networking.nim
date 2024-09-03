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
  kzg4844/[kzg, kzg_abi],
  stint,
  eth/p2p/discoveryv5/[node],
  ../../beacon_chain/spec/eip7594_helpers,
  ../testutil,
  ./fixtures_utils, ./os_ops

from std/sequtils import mapIt

proc runGetCustodyColumns(suiteName, path: string) =
  let relativePathComponent = path.relativeTestPathComponent()
  test "Networking - Get Custody Columns - " & relativePathComponent:
    type TestMetaYaml = object
      node_id: string
      custody_subnet_count: uint64
      result: seq[uint64]
    let
      meta = block:
        var s = openFileStream(path/"meta.yaml")
        defer: close(s)
        var res: TestMetaYaml
        yaml.load(s, res)
        res
      node_id = UInt256.fromDecimal(meta.node_id)
      custody_subnet_count = meta.custody_subnet_count
      reslt = (meta.result).mapIt(it)

    let columns = get_custody_columns(node_id, custody_subnet_count)

    for i in 0..<columns.lenu64:
      check columns[i] == reslt[i]

suite "EF - EIP7594 - Networking" & preset():
  const presetPath = SszTestsDir/const_preset
  let basePath =
    presetPath/"eip7594"/"networking"/"get_custody_columns"/"pyspec_tests"
  for kind, path in walkDir(basePath, relative = true, checkDir = true):
    runGetCustodyColumns(suiteName, basePath/path)