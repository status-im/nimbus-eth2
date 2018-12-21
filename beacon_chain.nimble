packageName   = "beacon_chain"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "Eth2.0 research implementation of the beacon chain"
license       = "MIT or Apache License 2.0"
installDirs   = @["beacon_chain", "research"]
bin           = @[
  "beacon_chain/beacon_node",
  "beacon_chain/validator_keygen",
  "research/state_sim"]

### Dependencies
requires "nim >= 0.18.0",
  "eth_common",
  "eth_keys",
  "nimcrypto",
  "https://github.com/status-im/nim-milagro-crypto#master",
  "eth_p2p",
  "ranges",
  "chronicles",
  "confutils",
  "serialization",
  "json_serialization",
  "json_rpc",
  "cligen 0.9.18"

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
