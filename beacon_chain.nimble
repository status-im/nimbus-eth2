mode = ScriptMode.Verbose

version       = "1.4.2"
author        = "Status Research & Development GmbH"
description   = "The Nimbus beacon chain node is a highly efficient Ethereum 2.0 client"
license       = "MIT or Apache License 2.0"

requires(
  "nim >= 1.2.0",
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

namedBin = {
  "beacon_chain/nimbus_beacon_node": "nimbus_beacon_node",
  "beacon_chain/nimbus_validator_client": "nimbus_validator_client",
  "ncli/ncli": "ncli",
}.toTable()

binDir = "build"

skipDirs = @[
  ".github",
  ".vscode"
  "docker",
  "grafana",
  "installer".
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
