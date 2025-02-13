# beacon_chain
# Copyright (c) 2024-2025 Status Research & Development GmbH
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
  ../../beacon_chain/spec/peerdas_helpers,
  ../testutil,
  ./fixtures_utils, ./os_ops

proc runComputeForCustodyGroup(suiteName, path: string) =
  let relativeTestPathComponent = path.relativeTestPathComponent()
  test "Networking - Compute Columns for Custody Group - " &
      relativeTestPathComponent:
    type TestMetaYaml = object
      custody_group: uint64
      result: seq[uint64]
    let
      meta = block:
        var s = openFileStream(path/"meta.yaml")
        defer: close(s)
        var res: TestMetaYaml
        yaml.load(s, res)
        res
      custody_group = meta.custody_group

    var counter = 0
    for column in compute_columns_for_custody_group(custody_group):
      check column == meta.result[counter]
      inc counter

proc runGetCustodyGroups(suiteName, path: string) =
  let relativePathComponent = path.relativeTestPathComponent()
  test "Networking - Get Custody Groups - " & relativePathComponent:
    type TestMetaYaml = object
      node_id: string
      custody_group_count: uint64
      result: seq[uint64]
    let
      meta = block:
        var s = openFileStream(path/"meta.yaml")
        defer: close(s)
        var res: TestMetaYaml
        yaml.load(s, res)
        res
      node_id = UInt256.fromDecimal(meta.node_id)
      custody_group_count = meta.custody_group_count

    let columns = get_custody_groups(node_id, custody_group_count)

    for i in 0..<columns.lenu64:
      check columns[i] == meta.result[i]

suite "EF - PeerDAS - Networking" & preset():
  const presetPath = SszTestsDir/const_preset
  # foldering to be resolved in alpha 11 release of consensus spec tests
  block:
    let basePath =
      presetPath/"fulu"/"networking"/"get_custody_groups"/"pyspec_tests"
    for kind, path in walkDir(basePath, relative = true, checkDir = true):
      runGetCustodyGroups(suiteName, basePath/path)
  block:
    let basePath =
      presetPath/"fulu"/"networking"/"compute_columns_for_custody_group"/"pyspec_tests"
    for kind, path in walkDir(basePath, relative = true, checkDir = true):
      runComputeForCustodyGroup(suiteName, basePath/path)
