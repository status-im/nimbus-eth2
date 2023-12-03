# beacon_chain
# Copyright (c) 2021-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.used.}

import
  unittest2, confutils,
  stew/byteutils,
  ../beacon_chain/el/el_conf,
  ../beacon_chain/spec/engine_authentication

type
  ExampleConfigFile = object
    dataDir* {.name: "data-dir".}: string
    el* {.name: "el".}: seq[EngineApiUrlConfigValue]

proc loadExampleConfig(content: string, cmdLine = newSeq[string]()): ExampleConfigFile =
  ExampleConfigFile.load(
    cmdLine = cmdLine,
    secondarySources = proc (
        config: ExampleConfigFile, sources: ref SecondarySources
    ) {.raises: [ConfigurationError].} =
      sources.addConfigFileContent(Toml, content))

const
  validJwtToken = parseJwtTokenValue(
    "aa95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098cc").get

suite "EL Configuration":
  test "URL parsing":
    let url1 = EngineApiUrlConfigValue.parseCmdArg("localhost:8484")
    check:
      url1.url == "localhost:8484"
      url1.roles.isNone
      url1.jwtSecret.isNone
      url1.jwtSecretFile.isNone

    let
      url1Final1 = url1.toFinalUrl(Opt.some validJwtToken)
      url1Final2 = url1.toFinalUrl(Opt.none seq[byte])

    check:
      url1Final1.isOk
      url1Final1.get.url == "ws://localhost:8484"
      url1Final1.get.jwtSecret.get == validJwtToken
      url1Final1.get.roles == defaultEngineApiRoles

      url1Final2.isOk
      url1Final2.get.url == "ws://localhost:8484"
      url1Final2.get.jwtSecret.isNone
      url1Final2.get.roles == defaultEngineApiRoles

    let url2 = EngineApiUrlConfigValue.parseCmdArg(
      "https://eth-node.io:2020#jwt-secret-file=tests/media/jwt.hex")
    check:
      url2.url == "https://eth-node.io:2020"
      url2.roles.isNone
      url2.jwtSecret.isNone
      url2.jwtSecretFile.get.string == "tests/media/jwt.hex"

    let url3 = EngineApiUrlConfigValue.parseCmdArg(
      "http://localhost/#roles=sync-deposits&jwt-secret=ee95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098ba")
    check:
      url3.url == "http://localhost/"
      url3.roles == some({DepositSyncing})
      url3.jwtSecret == some("ee95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098ba")
      url3.jwtSecretFile.isNone

    let url3Final = url3.toFinalUrl(Opt.some validJwtToken)
    check:
      url3Final.isOk
      url3Final.get.jwtSecret.get.toHex == "ee95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098ba"
      url3Final.get.roles == {DepositSyncing}

    let url4 = EngineApiUrlConfigValue.parseCmdArg(
      "localhost#roles=sync-deposits,validate-blocks&jwt-secret=ee95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098ba23")
    check:
      url4.url == "localhost"
      url4.roles == some({DepositSyncing, BlockValidation})
      url4.jwtSecret == some("ee95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098ba23")
      url4.jwtSecretFile.isNone

    let url4Final = url4.toFinalUrl(Opt.some validJwtToken)
    check:
      not url4Final.isOk # the JWT secret is invalid

    let url5 = EngineApiUrlConfigValue.parseCmdArg(
      "http://127.0.0.1:9090/#roles=sync-deposits,validate-blocks,produce-blocks,sync-deposits")
    check:
      url5.url == "http://127.0.0.1:9090/"
      url5.roles == some({DepositSyncing, BlockValidation, BlockProduction})
      url5.jwtSecret.isNone
      url5.jwtSecretFile.isNone

  test "Invalid URls":
    template testInvalidUrl(url: string) =
      expect ValueError:
        echo "This URL should be invalid: ", EngineApiUrlConfigValue.parseCmdArg(url)

    testInvalidUrl "http://127.0.0.1:9090/#roles="
    testInvalidUrl "http://127.0.0.1:9090/#roles=sy"
    testInvalidUrl "http://127.0.0.1:9090/#roles=sync-deposits,"
    testInvalidUrl "http://127.0.0.1:9090/#roles=sync-deposits;validate-blocks"
    testInvalidUrl "http://127.0.0.1:9090/#roles=validate-blocks,sync-deps"

  test "Old style config files":
    let cfg = loadExampleConfig """
      data-dir = "/foo"
      el = ["http://localhost:8585", "eth-data.io#roles=sync-deposits", "wss://eth-nodes.io/21312432"]
    """

    check:
      cfg.dataDir == "/foo"
      cfg.el.len == 3
      cfg.el[0].url == "http://localhost:8585"
      cfg.el[1].url == "eth-data.io"
      cfg.el[1].roles == some({DepositSyncing})
      cfg.el[2].url == "wss://eth-nodes.io/21312432"

  test "New style config files":
    let cfg = loadExampleConfig """
      data-dir = "my-data-dir"

      [[el]]
      url = "http://localhost:8585"
      jwt-secret-file = "tests/media/jwt.hex"

      [[el]]
      url = "eth-data.io"
      roles = ["sync-deposits", "produce-blocks"]

      [[el]]
      url = "wss://eth-nodes.io/21312432"
      jwt-secret = "0xee95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098ba"
    """

    check:
      cfg.dataDir == "my-data-dir"

      cfg.el.len == 3
      cfg.el[0].url == "http://localhost:8585"
      cfg.el[0].roles.isNone
      cfg.el[0].jwtSecret.isNone
      cfg.el[0].jwtSecretFile.get.string == "tests/media/jwt.hex"

      cfg.el[1].url == "eth-data.io"
      cfg.el[1].roles == some({DepositSyncing, BlockProduction})
      cfg.el[1].jwtSecret.isNone
      cfg.el[1].jwtSecretFile.isNone

      cfg.el[2].url == "wss://eth-nodes.io/21312432"
      cfg.el[2].roles.isNone
      cfg.el[2].jwtSecret.get == "0xee95565a2cc95553d4bf2185f58658939ba3074ce5695cbabfab4a1eaf7098ba"
      cfg.el[2].jwtSecretFile.isNone

  test "Empty config file":
    let cfg = loadExampleConfig("", cmdLine = @["--data-dir=foo"])

    check:
      cfg.dataDir == "foo"
      cfg.el.len == 0
