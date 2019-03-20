import
  beacon_chain/version as ver

packageName   = "beacon_chain"
version       = versionAsStr
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
  "blscurve",
  "ranges",
  "chronicles",
  "confutils",
  "serialization",
  "json_serialization",
  "json_rpc",
  "chronos",
  "yaml",
  "libp2p"

### Helper functions
proc test(name: string, defaultLang = "c") =
  if not dirExists "build":
    mkDir "build"
  --run
  switch("out", ("./build/" & name))
  switch("opt", "speed")
  setCommand defaultLang, "tests/" & name & ".nim"

### tasks
task test, "Run all tests":
  test "all_tests"
