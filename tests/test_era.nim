# beacon_chain
# Copyright (c) 2025-2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}
{.used.}

import
  unittest2,
  ../beacon_chain/spec/[digest, presets],
  ../ncli/era

func testRoot(): Eth2Digest =
  for i in 0 ..< result.data.len:
    result.data[i] = byte(i)

template cfgWithName(configName: string): RuntimeConfig =
  var cfg = defaultRuntimeConfig
  cfg.CONFIG_NAME = configName
  cfg

suite "era file names":
  test "round-trip generated era file names":
    # `CONFIG_NAME` is free-form and may contain `-` - it only has to match the
    # regex `[a-z0-9\-]` - so the round-trip must hold for such networks too
    for configName in ["mainnet", "sepolia", "my-testnet", "a-b-c-d"]:
      let cfg = cfgWithName(configName)
      for era in [0'u64, 1, 12, 9999, 99999, 100000]:
        let
          name = eraFileName(cfg, Era(era), testRoot())
          parsed = Era.fromEraFile(cfg, name)

        check parsed.isSome()
        if parsed.isSome():
          check parsed.get() == Era(era)

  test "accept era numbers longer than five digits":
    # `eraFileName` zero-fills the era number to _at least_ five digits - names
    # it produces must therefore parse back even once they grow past that
    let cfg = cfgWithName("mainnet")
    check Era.fromEraFile(cfg, "mainnet-100000-abcdef01.era").get() == Era(100000)

  test "reject era file names of another network":
    let cfg = cfgWithName("my-testnet")
    for name in [
        "testnet-00012-abcdef01.era", "my-00012-abcdef01.era",
        "my-testne-00012-abcdef01.era", "my-testnetx-00012-abcdef01.era"]:
      check Era.fromEraFile(cfg, name).isNone()

  test "reject malformed era file names":
    let cfg = cfgWithName("mainnet")
    for name in [
        "mainnet-00012-abcdef01.bin", "mainnet-0012-abcdef01.era",
        "mainnet-abcde-abcdef01.era", "mainnet-00012abcdef01.era",
        "mainnet-00012-.era", "sepolia-00012-abcdef01.era",
        "00012-abcdef01.era", ".era", "mainnet-"]:
      check Era.fromEraFile(cfg, name).isNone()
