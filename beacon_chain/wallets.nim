# beacon_chain
# Copyright (c) 2018-2025 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/os,
  ./spec/defects,
  ./validators/keystore_management,
  ./conf

proc doWallets*(config: BeaconNodeConf, rng: var HmacDrbgContext) =
  case config.walletsCmd:
  of WalletsCmd.create:
    if config.createdWalletNameFlag.isSome:
      let
        name = config.createdWalletNameFlag.get
        existingWallet = findWallet(config, name).valueOr:
          fatal "Failed to locate wallet", reason = error
          raiseWalletsDefect()
      if existingWallet.isSome:
        echo "The Wallet '" & name.string & "' already exists."
        raiseWalletsDefect()

    let walletOpt = createWalletInteractively(rng, config).valueOr:
      fatal "Unable to create wallet", reason = error
      raiseWalletsDefect()
    var wallet = walletOpt.valueOr:
      fatal "Process interrupted by user"
      raiseWalletsDefect()
    burnMem(wallet.seed)

  of WalletsCmd.list:
    try:
      for kind, walletFile in walkDir(config.walletsDir):
        if kind != pcFile: continue
        if checkSensitiveFilePermissions(walletFile):
          let walletRes = loadWallet(walletFile)
          if walletRes.isOk:
            echo walletRes.get.longName
          else:
            warn "Found corrupt wallet file",
                  wallet = walletFile, error = walletRes.error
        else:
          warn "Found wallet file with insecure permissions",
                wallet = walletFile
    except OSError as exc:
      fatal "Unable to create wallets list", reason = exc.msg
      raiseWalletsDefect()

  of WalletsCmd.restore:
    restoreWalletInteractively(rng, config)
