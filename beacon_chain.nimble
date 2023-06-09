# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

mode = ScriptMode.Verbose

version       = "1.4.2"
author        = "Status Research & Development GmbH"
description   = "The Nimbus beacon chain node is a highly efficient Ethereum 2.0 client"
license       = "MIT or Apache License 2.0"

requires(
  "nim >= 1.6.12",
  "https://github.com/status-im/NimYAML",
  "bearssl",
  "blscurve",
  "chronicles",
  "chronos",
  "confutils",
  "eth",
  "faststreams",
  "httputils",
  "json_rpc",
  "json_serialization",
  "libbacktrace",
  "libp2p",
  "metrics",
  "nat_traversal",
  "nimcrypto",
  "normalize",
  "presto",
  "secp256k1",
  "serialization",
  "snappy",
  "sqlite3_abi",
  "ssz_serialization",
  "stew",
  "stint",
  "taskpools",
  "testutils",
  "unicodedb >= 0.10",
  "unittest2",
  "web3",
  "zlib",
  "zxcvbn"
)

requires "https://gitlab.com/status-im/nimbus-security-resources.git"

import tables
let namedBin = {
  "beacon_chain/nimbus_beacon_node": "nimbus_beacon_node",
  "beacon_chain/nimbus_validator_client": "nimbus_validator_client",
  "ncli/ncli": "ncli",
}.toTable()

binDir = "build"

skipDirs = @[
  ".github",
  ".vscode",
  "docker",
  "grafana",
  "installer",
  "media",
  "nfuzz",
  "research",
  "scripts",
  "tests",
  "tools",
  "vendor",
  "wasm",
]

proc getLang(): string =
  var lang = "c"
  if existsEnv"TEST_LANG":
    lang = getEnv"TEST_LANG"
  lang

proc test(name: string, defaultLang = getLang()) =
  if not dirExists "build":
    mkDir "build"
  --run
  switch("out", ("./build/" & name))
  setCommand defaultLang, "tests/" & name & ".nim"

task test, "Run all tests":
  test "all_tests"
