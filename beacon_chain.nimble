packageName   = "beacon_chain"
version       = "0.0.1"
author        = "Status Research & Development GmbH"
description   = "Eth2.0 research implementation of the beacon chain"
license       = "MIT or Apache License 2.0"
srcDir        = "src"

### Dependencies
requires "nim >= 0.18.0",
  "eth_common",
  "nimcrypto",
  "https://github.com/status-im/nim-milagro-crypto#master"

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
