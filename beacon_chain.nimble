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
  "research/serialized_sizes",
  "research/state_sim",
  ]

### Dependencies
requires "nim >= 0.19.0",
  "blscurve",
  "chronicles",
  "chronos",
  "confutils",
  "eth",
  "json_rpc",
  "json_serialization",
  "libp2p",
  "metrics",
  "nimcrypto",
  "serialization",
  "stew",
  "prompt",
  "web3",
  "yaml"

### Helper functions
proc buildBinary(name: string, srcDir = "./", params = "", cmdParams = "", lang = "c") =
  if not dirExists "build":
    mkDir "build"
  # allow something like "nim test --verbosity:0 --hints:off beacon_chain.nims"
  var extra_params = params
  for i in 2..<paramCount():
    extra_params &= " " & paramStr(i)
  exec "nim " & lang & " --out:./build/" & name & " " & extra_params & " " & srcDir & name & ".nim" & " " & cmdParams

### tasks
task test, "Run all tests":
  # Mainnet config
  buildBinary "all_tests", "tests/", "-r -d:release -d:chronicles_log_level=ERROR"
  # Minimal config
  buildBinary "all_tests", "tests/", "-r -d:release -d:chronicles_log_level=ERROR -d:const_preset=minimal"

  # Generic SSZ test, doesn't use consensus objects minimal/mainnet presets
  buildBinary "test_fixture_ssz_generic_types", "tests/official/", "-r -d:release -d:chronicles_log_level=DEBUG"

  # Consensus object SSZ tests
  #buildBinary "test_fixture_ssz_static", "tests/official/", "-r -d:release -d:chronicles_log_level=DEBUG -d:const_preset=minimal"
  #buildBinary "test_fixture_ssz_static", "tests/official/", "-r -d:release -d:chronicles_log_level=DEBUG -d:const_preset=mainnet"

  buildBinary "all_fixtures_require_ssz", "tests/official/", "-r -d:release -d:chronicles_log_level=DEBUG -d:const_preset=minimal"
  buildBinary "all_fixtures_require_ssz", "tests/official/", "-r -d:release -d:chronicles_log_level=DEBUG -d:const_preset=mainnet"

  # State sim; getting into 3rd epoch useful
  buildBinary "state_sim", "research/", "-r -d:release", "--validators=128 --slots=24"

task sync_lfs_tests, "Sync LFS json tests":
  # Syncs the json test files (but not the EF yaml tests)
  exec "scripts/setup_official_tests.sh"
