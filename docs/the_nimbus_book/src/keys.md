# Import your validator keys

!!! tip
    `systemd` service file users will want to follow the [service file guide](./beacon-node-systemd.md#import-validator-keys) instead!

Having followed the [deposit](./deposit.md) guide, you will have a `validator_keys` folder containing several `.json` files in the `nimbus-eth2` directory.

We'll import the signing key of each validator to the [data directory](./data-dir.md) using the `deposits import` command:

!!! note ""
    You'll be asked to enter the password you used when creating your keystore(s).

=== "Mainnet"
    ```sh
    build/nimbus_beacon_node deposits import --data-dir=build/data/shared_mainnet_0
    ```

=== "Prater"
    ```sh
    build/nimbus_beacon_node deposits import --data-dir=build/data/shared_prater_0
    ```

On success, a message will be printed that your keys have been imported:
```
NOT 2022-07-19 17:36:37.578+02:00 Keystore imported
```

!!! note ""
    `NOT` is short for `NOTICE` and not not :)

After importing keys, it's time to [restart](./connect-eth2.md) the node and check that the keys have been picked up by the beacon node.

!!! info "All the keys"
    You can read more about the different types of keys [here](https://blog.ethereum.org/2020/05/21/keys/) - the `deposit import` command will import the **signing key** only.

## Command line

If your `validator_keys` folder is stored elsewhere, you can pass its location to the import command:

=== "Mainnet"
    ```sh
    build/nimbus_beacon_node deposits import \
      --data-dir=build/data/shared_mainnet_0 \
      /path/to/keys
    ```

=== "Prater"
    ```sh
    build/nimbus_beacon_node deposits import \
      --data-dir=build/data/shared_prater_0 \
      /path/to/keys
    ```

Replacing `/path/to/keys` with the full pathname of where the `validator_keys` directory is found.

## Optimised import for a large number of validators

If you plan to use a large number of validators (e.g. more than 100) on a single beacon node or a validator client, you might benefit from running the `deposits import` command with the option `--method=single-salt`. This will force Nimbus to use the same password and random salt value when encrypting all of the imported keystores which will later enable it to load the large number of validator keys almost instantly. The theoretical downside of using this approach is that it makes the brute-force cracking of all imported keystores computationally equivalent to cracking just one of them. Nevertheless, the security parameters used by Ethereum are such that cracking even a single keystore is considered computationally infeasible with current hardware.

## Troubleshooting

If you come across an error, make sure that:

* You are using the correct [data directory](./data-dir.md)
    * for `systemd` users, look for the `--data-dir` option in the `.service` file
* You are running the command as the correct user
    * for `systemd` users, look for the `User=` option in the `.service`. Assuming the user is called `nimbus`,  prefix all commands with: `sudo -u nimbus`
* Permissions for the data directory are wrong
    * See [folder permissions](./data-dir.md#permissions) for how to fix this.
