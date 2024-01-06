# beacon_chain
# Copyright (c) 2022-2023 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

import
  std/os,
  confutils,
  ../beacon_chain/validators/keystore_management,
  ../beacon_chain/spec/[keystore, crypto],
  ../beacon_chain/conf

type
  Config = object
    threshold {.
      desc: "Used to generate distributed keys"
      name: "threshold" }: uint32

    remoteSignersUrls {.
      desc: "URLs of the remote signers"
      name: "remote-signer" }: seq[string]

    dataDir {.
      defaultValue: config.defaultDataDir()
      defaultValueDesc: ""
      desc: "A Nimbus data directory"
      name: "data-dir" }: InputDir

    validatorsDirFlag* {.
      desc: "A directory containing validator keystores"
      name: "validators-dir" }: Option[InputDir]

    secretsDirFlag* {.
      desc: "A directory containing validator keystore passwords"
      name: "secrets-dir" }: Option[InputDir]

    key {.
      desc: "A public key of the keystore"
      name: "key" }: string

    outDir {.
      desc: "A directory to store the generated validator keystores"
      name: "out-dir" }: OutDir

proc main =
  let conf = load Config
  if conf.threshold == 0:
    error "The specified treshold must be greater than zero"
    quit 1

  if conf.remoteSignersUrls.len == 0:
    error "Please specify at least one remote signer URL"
    quit 1

  if conf.threshold > conf.remoteSignersUrls.len.uint32:
    error "The specified treshold must be lower or equal to the number of signers"
    quit 1

  let rng = HmacDrbgContext.new()
  template rngCtx: untyped = rng[]

  let
    validatorsDir = conf.validatorsDir
    secretsDir = conf.secretsDir
    keystore = loadKeystore(validatorsDir,
                            secretsDir,
                            conf.key, true, nil).valueOr:
      error "Can't load keystore", validatorsDir, secretsDir, pubkey = conf.key
      quit 1

    signingPubKey = keystore.pubkey
    sharesCount = uint32 conf.remoteSignersUrls.len
    shares = generateSecretShares(keystore.privateKey,
                                  rngCtx,
                                  conf.threshold,
                                  sharesCount).valueOr:
      error "Failed to generate distributed key: ",
            threshold = conf.threshold, sharesCount
      quit 1

  if not signingPubKey.confirmShares(shares, rngCtx):
    error "Secret shares can't reconstruct original signature. " &
          "Distributed key will not be generated."
    quit 1

  let
    outSharesDir = conf.outDir / "shares"
    status = generateDistributedStore(
      rngCtx,
      shares,
      signingPubKey,
      0,
      outSharesDir / "secrets",
      outSharesDir / "validators",
      string conf.outDir,
      conf.remoteSignersUrls,
      conf.threshold)

  if status.isErr:
    error "Failed to generate distributed keystore", err = status.error
    quit 1

main()
