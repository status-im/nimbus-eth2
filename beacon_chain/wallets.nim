# Copyright (c) 2018-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

{.push raises: [].}

import
  std/os,
  ./validators/keystore_management,
  ./conf

proc doWallets*(config: BeaconNodeConf, rng: var HmacDrbgContext) {.
    raises: [Defect, CatchableError].} =
  case config.walletsCmd:
  of WalletsCmd.create:
    if config.createdWalletNameFlag.isSome:
      let
        name = config.createdWalletNameFlag.get
        existingWallet = findWallet(config, name).valueOr:
          fatal "Failed to locate wallet", error = error
          quit 1
      if existingWallet.isSome:
        echo "The Wallet '" & name.string & "' already exists."
        quit 1

    var wallet = createWalletInteractively(rng, config).valueOr:
      fatal "Unable to create wallet", err = error
      quit 1
    burnMem(wallet.seed)

  of WalletsCmd.list:
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

  of WalletsCmd.restore:
    restoreWalletInteractively(rng, config)
