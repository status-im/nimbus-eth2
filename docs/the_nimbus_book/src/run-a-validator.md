# Validating

Once your beacon node is [running](./quick-start.md), the next step is to set up a validator.

Nimbus **doesn't require** setting up a separate validator client process — the beacon node can itself perform validator duties.
This is a simple, safe and efficient way to get started.

!!! tip "Separate validator client"

    While not needed, advanced users may want to use a [separate validator client](./validator-client.md) instead.



## Overview

To start validating, you need to do these three steps, explained in more detail below:

1. [Make a deposit](./run-a-validator.md#1-make-a-deposit-for-your-validator) for your validator.
2. [Import your validator keys](./run-a-validator.md#2-import-your-validator-keys) into Nimbus.
3. [Start performing validator duties](./run-a-validator.md#3-start-validating) by restarting the node.



## 1. Make a deposit for your validator

To make a deposit, you will need to generate keys then submit a deposit transaction to the execution chain.

!!! tip "Launchpad"
    The process of setting up a validator is also documented at the Ethereum launchpad site:

    * [Mainnet](https://launchpad.ethereum.org/)
    * [Holesky EthStaker Launchpad](https://holesky.launchpad.ethstaker.cc/en/) or [Holesky EF Launchpad](https://holesky.launchpad.ethereum.org/)

!!! tip
    Before running your validator on Mainnet, you can (and should) verify that your setup works as expected by running it on the [Holesky testnet](./holesky.md).


### 1. Download the deposit tool

Start by downloading and unpacking the [deposit tool](https://github.com/ethereum/staking-deposit-cli/releases/latest) provided by the Ethereum Foundation:

```sh
# Enter the nimbus folder
cd nimbus-eth2

# Make sure to get the latest version from the download page
wget https://github.com/ethereum/staking-deposit-cli/releases/download/v2.2.0/staking_deposit-cli-9ab0b05-linux-amd64.tar.gz

# Unpack the archive
tar xvf staking_deposit-cli-9ab0b05-linux-amd64.tar.gz --strip-components 2
```

### 2. Generate keys

!!! tip "Live image"
    You can increase the security of this process by downloading a [Live Linux image](https://ubuntu.com/tutorials/try-ubuntu-before-you-install). To do so, copy `deposit` to a USB stick, boot into the live image, and run the tool from inside the image.
    Make sure you **don't** enable Wi-Fi and unplug any Ethernet cables when using this process.

The deposit tool generates a seed phrase, and uses this to create validator and withdrawal keys.

!!! danger "Seed phrase"
    If you lose you seed phrase and your withdrawal key, your funds will be lost forever!

=== "Mainnet"
    ```sh
    # Run the deposit tool and follow the instructions on screen
    ./deposit new-mnemonic --chain mainnet
    ```

=== "Holesky"
    ```sh
    # Run the deposit tool and follow the instructions on screen
    ./deposit new-mnemonic --chain holesky
    ```

### 3. Make the deposit

Once created, the keys are used to create a deposit transaction on the Ethereum execution chain.
Follow the instructions [here](https://launchpad.ethereum.org/en/upload-deposit-data) to upload the deposit data.

!!! warning
    If you are making a mainnet deposit make sure you verify that the deposit contract you are interacting with is the correct one.

    You should verify that the address is indeed: [0x00000000219ab540356cBB839Cbe05303d7705Fa](https://etherscan.io/address/0x00000000219ab540356cBB839Cbe05303d7705Fa)

Once you send off your transaction(s), before your validator starts producing blocks and attestations, there are two waiting periods.

First, you wait for the beacon chain to recognize the block containing the deposit.
This usually takes around 13 hours.
Then, you wait in the queue for validator activation.

Getting through the queue may take a few hours or days (assuming the chain is finalizing).
No validators are accepted into the validator set while the chain isn't finalizing.
The `Pending Validators` metric on the [beaconcha.in](https://beaconcha.in/) will give you the size of the queue.


With the keys created, you're ready for the next step: importing your validator keys.




## 2. Import your validator keys

!!! tip
    `systemd` service file users will want to follow the [service file guide](./beacon-node-systemd.md#import-validator-keys) instead!

By finishing the first step, you will have a `validator_keys` folder containing several `.json` files in the `nimbus-eth2` directory.

We'll import the signing key of each validator to the [data directory](./data-dir.md) using the `deposits import` command:

!!! note ""
    You'll be asked to enter the password you used when creating your keystore(s).

=== "Mainnet"
    ```sh
    build/nimbus_beacon_node deposits import --data-dir=build/data/shared_mainnet_0
    ```

=== "Holesky"
    ```sh
    build/nimbus_beacon_node deposits import --data-dir=build/data/shared_holesky_0
    ```

On success, a message will be printed that your keys have been imported:
```
NTC 2022-07-19 17:36:37.578+02:00 Keystore imported
```

After importing keys, it is time to [restart the node](./run-a-validator.md#3-start-validating) and check that the keys have been picked up by the beacon node.

!!! info "All the keys"
    You can read more about the different types of keys [here](https://blog.ethereum.org/2020/05/21/keys/) — the `deposits import` command will import the **signing key** only.


### Command line

If your `validator_keys` folder is stored elsewhere, you can pass its location to the import command:

=== "Mainnet"
    ```sh
    build/nimbus_beacon_node deposits import \
      --data-dir=build/data/shared_mainnet_0 \
      /path/to/keys
    ```

=== "Holesky"
    ```sh
    build/nimbus_beacon_node deposits import \
      --data-dir=build/data/shared_holesky_0 \
      /path/to/keys
    ```

Replacing `/path/to/keys` with the full pathname of where the `validator_keys` directory is found.


### Optimized import for a large number of validators

If you plan to use a large number of validators (e.g. more than 100) on a single beacon node or a validator client, you might benefit from running the `deposits import` command with the option `--method=single-salt`.
This will force Nimbus to use the same password and random salt value when encrypting all of the imported keystores which will later enable it to load the large number of validator keys almost instantly.
The theoretical downside of using this approach is that it makes the brute-force cracking of all imported keystores computationally equivalent to cracking just one of them.
Nevertheless, the security parameters used by Ethereum are such that cracking even a single keystore is considered computationally infeasible with current hardware.


### Troubleshooting

If you come across an error, make sure that:

* You are using the correct [data directory](./data-dir.md).
  For `systemd` users, look for the `--data-dir` option in the `.service` file.
* You are running the command as the correct user.
  For `systemd` users, look for the `User=` option in the `.service`. Assuming the user is called `nimbus`,  prefix all commands with: `sudo -u nimbus`.
* Permissions for the data directory are wrong.
  See [folder permissions](./data-dir.md#permissions) for how to fix this.




## 3. Start validating

Once your keys have been imported, it is time to configure a [fee recipient](./suggested-fee-recipient.md) and restart the beacon node to start validating.


### 1. Choose a fee recipient

The [fee recipient](./suggested-fee-recipient.md) is an Ethereum address that receives transaction fees from the blocks that your validators produce.
You can set up a separate address or reuse the address from which you funded your deposits.

### 2. (Re)start the node

Press `Ctrl-c` to stop the beacon node if it's running, then use the same command as before to run it again, this time adding the `--suggested-fee-recipient` option in addition to `--web3-url`:

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh --web3-url=http://127.0.0.1:8551 --suggested-fee-recipient=0x...
    ```

=== "Holesky"
    ```sh
    ./run-holesky-beacon-node.sh --web3-url=http://127.0.0.1:8551 --suggested-fee-recipient=0x...
    ```

### 3. Check the logs

Your beacon node will launch and connect your validator to the beacon chain network.
To check that keys were imported correctly, look for `Local validator attached` in the logs:

```
INF 2020-11-18 11:20:00.181+01:00 Launching beacon node
...
NTC 2020-11-18 11:20:02.091+01:00 Local validator attached
```

Congratulations!
Your node is now ready to perform validator duties and earning a small amount of ETH every 6.4 minutes in return for keeping the Ethereum network secure!
Depending on when the deposit was made, it may take a while before the first attestation is sent — this is normal.



!!! success "What next?"
    While that's all there is to it, it is essential that you both [keep an eye on your validator](keep-an-eye.md) and [keep Nimbus updated](keep-updated.md) regularly. 💫
