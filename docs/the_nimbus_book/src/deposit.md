# Make a deposit for your validator

To make a deposit, you will need to generate keys then submit a deposit transaction to the execution chain.

!!! tip "Launchpad"
    The process of setting up a validator is also documented at the Ethereum launchpad site:

    * [Mainnet](https://launchpad.ethereum.org/)
    * [Goerli/Prater EthStaker Launchpad](https://goerli.launchpad.ethstaker.cc/en/) or [Goerli/Prater EF Launchpad](https://prater.launchpad.ethereum.org/)

!!! tip
    Use Prater to stress test and future proof your set up against peak mainnet load.
    See [here](./prater.md) for all you need to know.

## Steps

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
    You can increase the security of this process by downloading a [Live linux image](https://ubuntu.com/tutorials/try-ubuntu-before-you-install). To do so, copy `deposit` to a USB stick, boot into the live image, and run the tool from inside the image.
    Make sure you **don't** enable Wifi and unplug any Ethernet cables when using this process.

The deposit tool generates a seed phrase, and uses this to create validator and withdrawal keys.

!!! danger "Seed phrase"
    If you lose you seed phrase and your withdrawal key, your funds will be lost forever!

=== "Mainnet"
    ```sh
    # Run the deposit tool and follow the instructions on screen
    ./deposit new-mnemonic --chain mainnet
    ```

=== "Prater"
    ```sh
    # Run the deposit tool and follow the instructions on screen
    ./deposit new-mnemonic --chain prater
    ```

### 3. Make the deposit

Once created, the keys are used to create a deposit transaction on the Ethereum execution chain.
Follow the instructions [here](https://launchpad.ethereum.org/en/upload-deposit-data) to upload the deposit data.

!!! warning
    If you are making a mainnet deposit make sure you verify that the deposit contract you are interacting with is the correct one.

    You should verify that the address is indeed: [0x00000000219ab540356cBB839Cbe05303d7705Fa](https://etherscan.io/address/0x00000000219ab540356cBB839Cbe05303d7705Fa)

!!! info
    Once you send off your transaction(s), your validator will be put in a queue based on deposit time.
    Getting through the queue may take a few hours or days (assuming the chain is finalizing).
    No validators are accepted into the validator set while the chain isn't finalizing.
    The `Pending Validators` metric on the [beaconcha.in](https://beaconcha.in/) will give you the size of the queue.

With the keys created, you're ready to perform the [key import](./keys.md).
