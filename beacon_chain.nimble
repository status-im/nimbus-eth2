mode = ScriptMode.Verbose

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
  "libp2p",
  "stew",
  "byteutils" # test only (BitField and bytes datatypes deserialization)

### Helper functions
proc buildBinary(name: string, srcDir = "./", params = "", lang = "c") =
  if not dirExists "build":
    mkDir "build"
  # allow something like "nim test --verbosity:0 --hints:off beacon_chain.nims"
  var extra_params = params
  for i in 2..<paramCount():
    extra_params &= " " & paramStr(i)
  exec "nim " & lang & " --out:./build/" & name & " " & extra_params & " " & srcDir & name & ".nim"

### tasks
task test, "Run all tests":
  # Mainnet config
  buildBinary "all_tests", "tests/", "-r -d:release -d:chronicles_log_level=ERROR"
  # Minimal config
  buildBinary "all_tests", "tests/", "-r -d:release -d:chronicles_log_level=ERROR -d:const_preset=minimal"
