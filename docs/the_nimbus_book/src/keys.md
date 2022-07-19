# Import your validator keys into Nimbus

Having followed the [deposit](./deposit.md) guide, you will have a `validator_keys` folder containing several `.json` files in the `nimbus-eth2` directory.

```admonish tip
You can read more about keys [here](https://blog.ethereum.org/2020/05/21/keys/)
```

We'll import the keys to Nimbus using the `deposits import` command:

**Mainnet**
```sh
build/nimbus_beacon_node deposits import --data-dir=build/data/shared_mainnet_0
```
**Prater**
```sh
build/nimbus_beacon_node deposits import --data-dir=build/data/shared_prater_0
```

```admonish note
You'll be asked to enter the password you created to encrypt your keystore(s).
```

If your `validator_keys` folder is stored elsewhere, you can pass its location to the import command:

**Prater**
```sh
build/nimbus_beacon_node deposits import --data-dir=build/data/shared_prater_0 /path/to/keys
```

**Mainnet**
```sh
build/nimbus_beacon_node deposits import --data-dir=build/data/shared_mainnet_0 /path/to/keys
```

Replacing `/path/to/keys` with the full pathname of where the `validator_keys` directory is found.

On success, a message will be printed that your keys have been imported:
```
NOT 2022-07-19 17:36:37.578+02:00 Keystore imported                          file=...
```

```admonish note
`NOT` is short for `NOTICE` and not not :)
```

```admonish note
If you're running the beacon node as a systemd service, for example because you followed a guide, you need to make sure you run the command as the same user that runs the service: prefix all commands with `sudo -u nimbus` to run them as `nimbus`.
```

After importing keys, it's time to [restart](./connect-eth2.md) the node and check that the keys have been picked up by the beacon node.

## Troubleshooting

If you come across an error, make sure that:

* You are using the correct data directory
  * for `systemd` users, look for the `--data-dir` option in the `.service` file
* You are running the command as the correct user
  * for `systemd` users, look for the `User=` option in the `.service`. Assuming the user is called `nimbus`,  prefix all commands with: `sudo -u nimbus`
* Permissions for the data directory are wrong
  * See [folder permissions](faq.md#folder-permissions) for how to fix this.
