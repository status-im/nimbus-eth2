# beacon_chain
# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/[json, strutils, times, sequtils],
  chronos, confutils, chronicles,
  web3, web3/primitives,
  eth/async_utils,
  ../beacon_chain/beacon_chain_db,
  ../beacon_chain/networking/network_metadata,
  ../beacon_chain/el/el_manager,
  ../beacon_chain/spec/[presets, helpers]

type
  CliFlags = object
    network* {.
      defaultValue: "mainnet"
      name: "network".}: string
    elUrls* {.
      name: "el".}: seq[EngineApiUrlConfigValue]
    jwtSecret* {.
      name: "jwt-secret".}: Option[InputFile]
    outDepositsFile* {.
      name: "out-deposits-file".}: Option[OutFile]
    configFile* {.
      desc: "Loads the configuration from a TOML file"
      name: "config-file" .}: Option[InputFile]

proc main(flags: CliFlags) {.async.} =
  let
    db = BeaconChainDB.new("", inMemory = true)
    metadata = getMetadataForNetwork(flags.network)
    beaconTimeFn = proc(): BeaconTime =
      # BEWARE of this hack
      # The EL manager consults the current time in order to determine when the
      # transition configuration exchange should start. We assume Bellatrix has
      # just arrived which should trigger the configuration exchange and allow
      # the downloader to connect to ELs serving the Engine API.
      start_beacon_time(Slot(metadata.cfg.BELLATRIX_FORK_EPOCH * SLOTS_PER_EPOCH))

  let
    elManager = ELManager.new(
      metadata.cfg,
      metadata.depositContractBlock,
      metadata.depositContractBlockHash,
      db,
      toFinalEngineApiUrls(flags.elUrls, flags.jwtSecret),
      eth1Network = metadata.eth1Network)

  elManager.start()

  var depositsFile: File
  if flags.outDepositsFile.isSome:
    depositsFile = open(string flags.outDepositsFile.get, fmWrite)
    depositsFile.write(
      "block", ",",
      "validatorKey", ",",
      "withdrawalCredentials", "\n")
    depositsFile.flushFile()

  var blockIdx = 0
  while not elManager.isSynced():
    await sleepAsync chronos.seconds(1)

    if flags.outDepositsFile.isSome and
       elManager.eth1ChainBlocks.len > blockIdx:
      for i in blockIdx ..< elManager.eth1ChainBlocks.len:
        for deposit in elManager.eth1ChainBlocks[i].deposits:
          depositsFile.write(
            $elManager.eth1ChainBlocks[i].number, ",",
            $deposit.pubkey, ",",
            $deposit.withdrawal_credentials, "\n")
          depositsFile.flushFile()

      blockIdx = elManager.eth1ChainBlocks.len

  info "All deposits downloaded"

waitFor main(
  load(CliFlags,
       secondarySources = proc (
           config: CliFlags, sources: ref SecondarySources
       ) {.raises: [ConfigurationError].} =
        if config.configFile.isSome:
          sources.addConfigFile(Toml, config.configFile.get)))
