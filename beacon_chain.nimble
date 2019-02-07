packageName   = "beacon_chain"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "Eth2.0 research implementation of the beacon chain"
license       = "MIT or Apache License 2.0"
installDirs   = @["beacon_chain", "research"]
bin           = @[
  "beacon_chain/beacon_node",
  "beacon_chain/validator_keygen",
  "research/serialized_sizes",
  "research/state_sim",
  ]

### Dependencies
requires "nim >= 0.19.0",
  "eth",
  "nimcrypto",
  "https://github.com/status-im/nim-blscurve#master",
  "ranges",
  "chronicles",
  "confutils",
  "serialization",
  "json_serialization",
  "json_rpc",
  "chronos"

### Helper functions
proc test(name: string, defaultLang = "c") =
  # TODO, don't forget to change defaultLang to `cpp` if the project requires C++
  if not dirExists "build":
    mkDir "build"
  --run
  switch("out", ("./build/" & name))
  setCommand defaultLang, "tests/" & name & ".nim"

### tasks
task test, "Run all tests":
  test "all_tests"
