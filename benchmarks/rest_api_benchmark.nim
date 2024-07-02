# beacon_chain
# Copyright (c) 2022-2024 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  chronicles, chronicles/[topics_registry, timings],
  confutils, confutils/std/net,
  ../beacon_chain/spec/eth2_apis/rest_beacon_client

type
  Config = object
    serverIpAddress {.
      defaultValue: static(parseIpAddress("127.0.0.1"))
      defaultValueDesc: "127.0.0.1"
      desc: "IP address of the beacon node's REST server"
      abbr: "a"
      name: "address" }: IpAddress

    serverPort {.
      defaultValue: 5052
      desc: "Listening port of the beacon node's REST server"
      abbr: "p"
      name: "port" }: Port

    startSlot {.
      defaultValue: 0
      desc: "The starting slot from which to start history traversal"
      abbr: "s"
      name: "start-slot" }: uint

    requestsCount {.
      desc: "Number of requests to send to the beacon node's REST server"
      abbr: "n"
      name: "count" }: uint

proc main() {.raises: [ConfigurationError, HttpError, OSError].} =
  let config = Config.load
  let serverAddress = initTAddress(config.serverIpAddress, config.serverPort)
  let client = RestClientRef.new(serverAddress)

  setLogLevel(LogLevel.INFO)

  template benchmark(apiNameIdent: untyped): untyped {.dirty.} =
    block:
      const apiName = astToStr apiNameIdent
      info "Benchmarking ...", apiName
      info.logTime(apiName):
        for slot in config.startSlot ..< (config.startSlot + config.requestsCount):
          let ident = StateIdent(kind: StateQueryKind.Slot, slot: slot.Slot)
          discard waitFor noCancel client.`apiNameIdent`(ident)

  benchmark(getStateRoot)
  benchmark(getStateForkPlain)
  benchmark(getStateFinalityCheckpoints)
  benchmark(getStateValidatorBalances)

when isMainModule:
  main()
