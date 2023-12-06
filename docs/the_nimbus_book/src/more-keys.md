# Recover lost keys and generate new ones

When generating your [first deposit](./run-a-validator.md#1-make-a-deposit-for-your-validator), you will be asked to save a mnemonic in a safe location.

This mnemonic can be used to recover lost keys and generate new ones.

Every time you generate a keystore from your mnemonic, that keystore is assigned an index.
The first keystore you generate has index 0, the second index 1, etc.
You can recover any key using your mnemonic and that key's index.
For more on how keys are derived, see this [excellent post](https://blog.ethereum.org/2020/05/21/keys/).

To stay consistent with the rest of the book, we'll take you though how to do this using the [deposit-cli's](https://github.com/ethereum/eth2.0-deposit-cli) [binary executable](https://github.com/ethereum/eth2.0-deposit-cli/releases).

Specifically, we'll be using the `existing-mnemonic` command.
Here's a description of the command from the deposit-cli's [README](https://github.com/ethereum/staking-deposit-cli#step-2-create-keys-and-deposit_data-json):

> This command is used to re-generate or derive new keys from your existing mnemonic.
Use this command, if (i) you have already generated keys with this CLI before, (ii) you want to reuse your mnemonic that you know is secure that you generated elsewhere (reusing your eth1 mnemonic .etc), or (iii) you lost your keystores and need to recover your keys.

## Recover existing key

!!! warning
    Recovering validator keys from a mnemonic should only be used as a last resort.
    Exposing your mnemonic to a computer at any time puts it at risk of being compromised.
    Your mnemonic is not encrypted and if leaked, can be used to steal your funds.

!!! note
    The commands below assume you are trying to recover the first key you created, hence `--validator_start_index` has been set to `0`.

Run the following command from the directory which contains the `deposit` executable:

=== "Mainnet"
    ```sh
    ./deposit existing-mnemonic \
    --validator_start_index 0 \
    --num_validators 1 \
    --chain mainnet
    ```

=== "Holesky"
    ```sh
    ./deposit existing-mnemonic \
    --validator_start_index 0 \
    --num_validators 1 \
    --chain holesky
    ```

You'll be prompted to enter your mnemonic, and a new password for your keystore.

Check that the `validator_keys` directory contains your keystore.

Copy the `validator_keys` directory to `nimbus-eth2` and then follow the [key import instructions](./run-a-validator.md#2-import-your-validator-keys) of our validator guide.
Your key will be added to your node on next restart.

## Generate another key

!!! warning
    If you wish to use your new key with a separate client instance, make sure not to include your first key in the second setup — doing so will lead to it being slashed!

!!! note
    The commands below assume you already have one key and wish to generate a second, hence `--validator_start_index` has been set to `1` (as `0` would be the original key)

Run the following command from the directory which contains the `deposit` executable:

=== "Mainnet"
    ```
    ./deposit existing-mnemonic \
    --validator_start_index 1 \
    --num_validators 1 \
    --chain mainnet
    ```

=== "Holesky"
    ```
    ./deposit existing-mnemonic \
    --validator_start_index 1 \
    --num_validators 1 \
    --chain holesky
    ```

You'll be prompted to enter your mnemonic and a new password for your keystore.

Check that the `validator_keys` directory contains an extra keystore.

Copy the `validator_keys` directory to `nimbus-eth2`.

Make sure you've [made a deposit](./run-a-validator.md#1-make-a-deposit-for-your-validator) for your new keystore, and then follow the [key import instructions](./run-a-validator.md#2-import-your-validator-keys) of our validator guide.
Your key will be added to your node on the next restart.
