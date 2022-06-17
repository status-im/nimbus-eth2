# Prater testnet

`prater` is a testnet that you can use to verify that your setup is ready for mainnet, as well as safely practise node operations such as adding and removing validators, migrating between clients and performing upgrades and backups.

The `prater` testnet is run by client teams, the Ethereum Foundation and community members.

Connecting to `prater` and setting up a validator follows the same procedure as a normal mainnet node with the following modifications:

* Validator deposits are done on the `goerli` testnet via the [Prater launchpad](https://prater.launchpad.ethereum.org/en/)
* To run a Prater node after making a deposit, [update Nimbus](./keep-updated.md) and then execute `./run-prater-beacon-node.sh` or use the `--network:prater` command line option.

## Custom testnets

You can connect to any network provided that you have a configuration and genesis file, using the `network` option:

```console
build/nimbus_beacon_node --network:path/to/network --data-dir:path/to/data
```

The network directory must have the same layout as the [eth2-networks](https://github.com/eth-clients/eth2-networks) repository testnets.

## Other testnets

Historical testnets can be found [here](https://github.com/eth-clients/eth2-networks).

* `pyrmont` - deprecated in favour of `prater` due to its small validator count compared to `mainnet`
* `insecura` - a spin-off of `prater` to demonstrate the [weak subjectivity attack](https://ethresear.ch/t/insecura-my-consensus-for-the-pyrmont-network)
* `medalla` - one of the first multi-client testnets, deprecated in favour of `pyrmont` to capture the latest 1.0 spec changes
