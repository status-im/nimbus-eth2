import
  std/os,
  bearssl, nimcrypto/utils, confutils, eth/keys,
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

    outValidatorsDir {.
      desc: "A directory to store the generated validator keystores"
      name: "out-validators-dir" }: OutDir

template valueOr(x: Option, elseBlock: untyped): untyped =
  let val = x
  if val.isSome:
    val.get
  else:
    elseBlock

proc main =
  var
    rng = keys.newRng()
    rngCtx = rng[]

  let
    conf = load Config
    validatorsDir = conf.validatorsDir
    secretsDir = conf.secretsDir
    keystore = loadKeystore(validatorsDir,
                            secretsDir,
                            conf.key, true).valueOr:
      error "Can't load keystore", validatorsDir, secretsDir, pubkey = conf.key
      quit 1

    signingPubKey = keystore.pubkey
    sharesCount = uint32 conf.remoteSignersUrls.len 
    shares = generateSecretShares(keystore.privateKey,
                                  rngCtx,
                                  conf.threshold,
                                  sharesCount).valueOr:
      error "Failed to generate distributed key: ", threshold = conf.threshold, sharesCount
      quit 1

  if not signingPubKey.confirmShares(shares, rngCtx):
    error "Secret shares can't reconstruct original signature. Distributed key will not be generated."
    quit 1

  let
    outSharesDir = conf.outValidatorsDir / "shares"
    status = generateDistirbutedStore(
      rngCtx,
      shares,
      signingPubKey,
      0,
      outSharesDir / "secret",
      outSharesDir / "validator",
      string conf.outValidatorsDir,
      conf.remoteSignersUrls,
      conf.threshold)

  if status.isErr:
    error "Failed to generate distributed keystore", err = status.error
    quit 1
