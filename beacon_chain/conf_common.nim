# beacon_chain
# Copyright (c) 2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import std/os
import "."/[conf, conf_light_client]
import results, confutils, confutils/defs, confutils/std/net,
       confutils/toml/defs as confTomlDefs,
       confutils/toml/std/net as confTomlNet,
       confutils/toml/std/uri as confTomlUri

proc makeBannerAndConfig*(clientId, copyright, banner, specVersion: string,
                          environment: openArray[string],
                          ConfType: type): Result[ConfType, string] =
  let
    version = clientId & "\p" & copyright & "\p\p" &
      "eth2 specification v" & specVersion & "\p\p" &
      banner
    cmdLine = if len(environment) == 0: commandLineParams()
              else: @environment

  # TODO for some reason, copyrights are printed when doing `--help`
  {.push warning[ProveInit]: off.}
  let config = try:
    ConfType.load(
      version = version, # but a short version string makes more sense...
      copyrightBanner = clientId,
      cmdLine = cmdLine,
      secondarySources = proc (
          config: ConfType, sources: auto
      ) {.raises: [ConfigurationError], gcsafe.} =
        if config.configFile.isSome:
          sources.addConfigFile(Toml, config.configFile.get)
    )
  except CatchableError as exc:
    # We need to log to stderr here, because logging hasn't been configured yet
    var msg = "Failure while loading the configuration:\p" & exc.msg & "\p"
    if (exc[] of ConfigurationError) and not(isNil(exc.parent)) and
       (exc.parent[] of TomlFieldReadingError):
      let fieldName = ((ref TomlFieldReadingError)(exc.parent)).field
      if fieldName in ["web3-url", "bootstrap-node",
                       "direct-peer", "validator-monitor-pubkey"]:
        msg &= "Since the '" & fieldName & "' option is allowed to " &
               "have more than one value, please make sure to supply " &
               "a properly formatted TOML array\p"
    return err(msg)
  {.pop.}
  ok(config)
