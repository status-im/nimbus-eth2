import
  confutils/defs

type
  ValidatorKeyPath* = distinct string

  Configuration* = object
    dataDir* {.
      desc: "The directory where nimbus will store all blockchain data.",
      shorthand: "d",
      defaultValue: getConfigDir() / "nimbus".}: DirPath

    bootstrapNodes* {.
      desc: "Specifies one or more bootstrap nodes to use when connecting to the network.",
      shorthand: "b".}: seq[string]

    tcpPort* {.
      desc: "TCP listening port".}: int

    udpPort* {.
      desc: "UDP listening port".}: int

    validatorKeys* {.
      desc: "A path to a pair of public and private keys for a validator. " &
            "Nimbus will automatically add the extensions .privkey and .pubkey.",
      shorthand: "v".}: seq[ValidatorKeyPath]

