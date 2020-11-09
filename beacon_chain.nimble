mode = ScriptMode.Verbose

import
  beacon_chain/version as ver

packageName   = "beacon_chain"
version       = versionAsStr
author        = "Status Research & Development GmbH"
description   = "Eth2.0 research implementation of the beacon chain"
license       = "MIT or Apache License 2.0"
installDirs   = @["beacon_chain", "research"]
skipDirs      = @["nfuzz"]
bin           = @[
  "beacon_chain/nimbus_beacon_node",
  "research/serialized_sizes",
  "nbench/nbench",
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
  "libbacktrace",
  "libp2p",
  "metrics",
  "nimcrypto",
  "normalize",
  "serialization",
  "stew",
  "testutils",
  "prompt",
  "unicodedb",
  "web3",
  "yaml",
  "zxcvbn"

### Helper functions
proc buildAndRunBinary(name: string, srcDir = "./", params = "", cmdParams = "", lang = "c") =
  if not dirExists "build":
    mkDir "build"
  # allow something like "nim test --verbosity:0 --hints:off beacon_chain.nims"
  var extra_params = params
  for i in 2..<paramCount():
    extra_params &= " " & paramStr(i)
  exec "nim " & lang & " --out:./build/" & name & " -r " & extra_params & " " & srcDir & name & ".nim" & " " & cmdParams

task moduleTests, "Run all module tests":
  buildAndRunBinary "nimbus_beacon_node", "beacon_chain/",
                    "-d:chronicles_log_level=TRACE " &
                    "-d:const_preset=minimal -d:ETH2_SPEC=\"v0.12.3\" " &
                    "-d:testutils_test_build"

### tasks
task test, "Run all tests":
  # We're enabling the TRACE log level so we're sure that those rarely used
  # pieces of code get tested regularly. Increased test output verbosity is the
  # price we pay for that.

  # TODO re-add minimal const sanity check for 1.0.0
  buildAndRunBinary "test_fixture_const_sanity_check", "tests/official/", """-d:const_preset=mainnet -d:ETH2_SPEC="v1.0.0" -d:chronicles_sinks="json[file]""""

  # Generic SSZ test, doesn't use consensus objects minimal/mainnet presets
  buildAndRunBinary "test_fixture_ssz_generic_types", "tests/official/", """-d:ETH2_SPEC="v1.0.0" -d:chronicles_log_level=TRACE -d:chronicles_sinks="json[file]""""

  # Consensus object SSZ tests
  # v0.12.3 is reasonably covered by rest of SSZ fixture tests and lack of
  # non-numeric-constant changes in SSZ types between v0.12.3 and v1.0.0.
  buildAndRunBinary "test_fixture_ssz_consensus_objects", "tests/official/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v1.0.0" -d:chronicles_sinks="json[file]""""

  # EF tests
  buildAndRunBinary "all_fixtures_require_ssz", "tests/official/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v1.0.0" -d:chronicles_sinks="json[file]""""

  # Mainnet config
  buildAndRunBinary "proto_array", "beacon_chain/fork_choice/", """-d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:chronicles_sinks="json[file]""""
  buildAndRunBinary "fork_choice", "beacon_chain/fork_choice/", """-d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:chronicles_sinks="json[file]""""
  buildAndRunBinary "all_tests", "tests/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:chronicles_sinks="json[file]""""
  # TODO `test_keystore` is extracted from the rest of the tests because it uses conflicting BLST headers
  buildAndRunBinary "test_keystore", "tests/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:chronicles_sinks="json[file]""""

  # Check Miracl/Milagro fallback on select tests
  buildAndRunBinary "test_interop", "tests/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:BLS_FORCE_BACKEND=miracl -d:chronicles_sinks="json[file]""""
  buildAndRunBinary "test_process_attestation", "tests/spec_block_processing/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:BLS_FORCE_BACKEND=miracl -d:chronicles_sinks="json[file]""""
  buildAndRunBinary "test_process_deposits", "tests/spec_block_processing/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:BLS_FORCE_BACKEND=miracl -d:chronicles_sinks="json[file]""""
  buildAndRunBinary "all_fixtures_require_ssz", "tests/official/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v0.12.3" -d:BLS_FORCE_BACKEND=miracl -d:chronicles_sinks="json[file]""""
  buildAndRunBinary "test_attestation_pool", "tests/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v1.0.0" -d:BLS_FORCE_BACKEND=miracl -d:chronicles_sinks="json[file]""""
  buildAndRunBinary "test_block_pool", "tests/", """-d:chronicles_log_level=TRACE -d:const_preset=mainnet -d:ETH2_SPEC="v1.0.0" -d:BLS_FORCE_BACKEND=miracl -d:chronicles_sinks="json[file]""""

  # State and block sims; getting to 4th epoch triggers consensus checks
  buildAndRunBinary "state_sim", "research/", "-d:const_preset=mainnet -d:ETH2_SPEC=\"v1.0.0\" -d:chronicles_log_level=INFO", "--validators=3000 --slots=128"
  # buildAndRunBinary "state_sim", "research/", "-d:const_preset=mainnet -d:ETH2_SPEC=\"v1.0.0\" -d:BLS_FORCE_BACKEND=miracl -d:chronicles_log_level=INFO", "--validators=3000 --slots=128"
  buildAndRunBinary "block_sim", "research/", "-d:const_preset=mainnet -d:ETH2_SPEC=\"v1.0.0\"", "--validators=3000 --slots=128"
  # buildAndRunBinary "block_sim", "research/", "-d:const_preset=mainnet -d:ETH2_SPEC=\"v1.0.0\" -d:BLS_FORCE_BACKEND=miracl", "--validators=3000 --slots=128"
