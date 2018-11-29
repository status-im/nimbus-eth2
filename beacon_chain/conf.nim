import
  confutils/defs

type
  ValidatorKeyPath* = distinct string

  BeaconNodeConf* = object
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

proc parse*(T: type ValidatorKeyPath, input: TaintedString): T =
  # TODO:
  # Check that the entered string is a valid base file name and
  # that it has matching .privkey, .pubkey and .randaosecret files
  T(input)

