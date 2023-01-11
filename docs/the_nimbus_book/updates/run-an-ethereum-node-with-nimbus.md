# Run an Ethereum node with Nimbus

This guide assists you in setting up an Ethereum node and running a validator using Nimbus and an execution client of your choice. To prevent asset loss, practice on the Goerli/Prater testnet before you use the Ethereum Mainnet.

## Prerequisites

Before you start, first learn the basics of [Ethereum :octicons-tab-external-16:](https://ethereum.org/en/developers/docs/intro-to-ethereum/){:target="_blank"} and how to use the command line. The guide assumes you run both clients on the same machine using Ubuntu Linux. Here are more detailed requirements for your system:

| Item | Requirement| Note |
|----|------| --- |
| Memory | 8 GB RAM| - |
| Storage| 2 TB SSD| Here's a list of [known good models :octicons-tab-external-16:](https://gist.github.com/yorickdowne/f3a3e79a573bf35767cd002cc977b038){:target="_blank"}. |
| Network |Broadband without data cap| Data consumption at 2-4 TB/month based on the number of your validtors and other load on the network. |
| Operating system | Linux 64-bit | - |

The backslashes "\" in the example commands are line breaks. You must remove them and convert the commands into one line of text before executing.

## Synchronize system time

Install [chrony :octicons-tab-external-16:](https://chrony.tuxfamily.org/){:target="_blank"} using the `apt-get install` command to ensure the system time is periodically synchronized with an NTP server.

```sh
sudo apt-get install -y chrony
```

## Install Nimbus

You need to download and install Nimbus to run a consensus client. Consensus clients allow the Ethereum network to reach an agreement.

1. Use the `mkdir` command to create a directory with the name `nimbus-eth2` to hold Nimbus applications.  
```sh
mkdir -p nimbus-eth2
```

1. Download the latest [Nimbus release :octicons-tab-external-16:](https://github.com/status-im/nimbus-eth2/releases){:target="_blank"} using the `wget` command. In the following command, replace `<version_number>` with the version number of the latest release, and replace `<name_of_the_release_package`>` with the name of the package to download. Choose the file that matches your Ubuntu architecture. 
```sh
wget https://github.com/status-im/nimbus-eth2/releases/download/<version_number>/<name_of_the_release_package>
```

    For example,
    ```sh
    wget https://github.com/status-im/nimbus-eth2/releases/download/v22.11.1/nimbus-eth2_Linux_arm64v8_22.11.1_e4b19337.tar.gz 
    ```
    
1. Unpack the `tar.gz` file using the `tar xvf` command into the `nimbus-eth2` directory. In the following command, replace `<name_of_the_release_package>` with the name of the package you downloaded.
```sh
tar xvf <name_of_the_release_package> --strip-components 1 -C nimbus-eth2
```

    For example,
    ```sh
    tar xvf nimbus-eth2_Linux_arm64v8_22.11.1_e4b19337.tar.gz --strip-components 1 -C nimbus-eth2
    ```

1. Create the `/var/lib/nimbus` folder using the `sudo mkdir` command as Nimbus data directory. 
```sh
sudo mkdir -p /var/lib/nimbus
```

1. Use `sudo chmod` to give the permissions to read and write data and execute files in the data directory.
```dotnetcli
sudo chmod 700 /var/lib/nimbus
```

## Run the Nimbus consensus client

After installing Nimbus, you can run the consensus client on the Ethereum Mainnet or the Goerli/Prater testnet, and download the blockchain data. 

1. Go to the Nimbus directory using the `cd` command.
```
cd nimbus-eth2
```

 1. Run the following command to start Nimbus and prepare for connecting to an execution client. 
 
    === "Mainnet"
        ```sh
        sudo ./run-mainnet-beacon-node.sh \
            --web3-url=http://127.0.0.1:8551 \
            --jwt-secret=/tmp/jwtsecret \
            --data-dir=/var/lib/nimbus/shared_mainnet_0

        ```

    === "Goerli/Prater"
        ```sh
        sudo ./run-prater-beacon-node.sh \
            --web3-url=http://127.0.0.1:8551 \
            --jwt-secret=/tmp/jwtsecret \
            --data-dir=/var/lib/nimbus/shared_prater_0
        ```

    Where:

    | Flag | Description |
    |------|-------------|
    | `--web3-url` | It informs Nimbus of the URL for connection. Nimbus can be connected to an execution client using an HTTP endpoint (`http://`) or a WebSockets endpoint (`ws://`). The default URL is `http://127.0.0.1:8551`. |
    | `--jwt-secret` | It informs Nimbus the path to the `jwtsecret` file, which is for communication with the execution client. You can learn more in the "Run an execution client" section. |
    | `--data-dir` | It designates the directory for storing Nimbus data. |

    Next, you can see this message:

    ```sh
    INF 2022-06-16 15:42:58.145+02:00 Launching beacon node                      topics="beacnde" version=v22.10.1-97a1cdc4-stateofus ...
    ```
    
    Nimbus automatically begins to look for peers and synchronize data from them, you can see log messages like this:

    ```
    INF 2022-06-16 13:23:11.008+02:00 Slot start
      topics="beacnde" slot=4046214 epoch=126444 sync="00h37m (99.38%) 11.0476slots/s (DDQQDDDPDD:4021215)" peers=55 head=5d59aba3:4021234 finalized=125661:82616f78 delay=8ms245us608ns
    ```
    
    Where:

    | Field | Description |
    |--------|------------|
    | `slot`| The current time on the chain measured in "slots". One slot = 12 seconds. | 
    | `epoch` | The current epoch. Each epoch has 32 slots. |
    | `sync` | The time left, sync progress (percentage), and sync speed. See below for information about `(DDQQDDDPDD:4021215)`. |
    | `peers` | The number of peers Nimbus is currently connected to. |
    | `head` | The most recent block synced to so far. In this example, `5d59aba3` is the first part of the block hash, `4021234` is the slot number. |
    | `finalized` | The most recent finalized epoch synced to so far. In this example, `125661` is the epoch, `82616f78` is the checkpoint hash. |
    | `delay` | The time delayed before processing the slot because the client is occupied with other computational work. |

    In `sync`, the string of numbers (`4021215` in this example) represents the slot number of the block being synced. The string of letters is the `sync worker map` (in this example, represented by `DDQQDDDPDD`). Each letter represents the status of one of the peers Nimbus is syncing from, where:
    
    ```
        s - sleeping (idle)
        w - waiting for a peer from the peer pool
        R - requesting blocks from the peer
        D - downloading blocks from the peer
        Q - queued/waiting for ancestor blocks
        P - processing/verifying blocks
        U - updating peer's status information
    ```

    Data synchronization may take hours to a few days.

## Run an execution client

Along with the consensus client, you need to set up an execution client. Execution clients are for processing and broadcasting transactions and managing Ethereum's state. Nimbus is tested with all [major execution clients :octicons-tab-external-16:](https://ethereum.org/en/developers/docs/nodes-and-clients/#execution-clients){:target="_blank"}, you can choose one that suits your needs.

The content here is from execution clients' documentation. Refer to their respective documentation sites for more details.

=== "Besu"

    1. Download and install Besu following the guide in the [Besu documentation :octicons-tab-external-16:](https://besu.hyperledger.org/en/stable/){:target="_blank"}

    1. Use the `openssl rand` command to create a `jwtsecret` file and store it in the `/tmp` directory. This file is a JSON web token for the clients to authenticate each other.
    ```bash
    openssl rand -hex 32 | tr -d "\n" > "/tmp/jwtsecret"
    ```

    1. Connect Besu to Nimbus. With the following command, you can start Besu, expose an RPC port (By default, Besu accepts requests from `localhost` and `127.0.0.1`) for Nimbus, pass the path to the `jwtsecret` file, and complete other relevant configuration.
    
        === "Mainnet"
            ```sh
            besu \
              --sync-mode=X_SNAP           \
              --data-storage-format=BONSAI \
              --rpc-http-enabled=true      \
              --rpc-http-host=0.0.0.0      \
              --rpc-ws-enabled=true        \
              --rpc-ws-host=0.0.0.0        \
              --host-allowlist=127.0.0.1,localhost        \
              --engine-host-allowlist=127.0.0.1,localhost \
              --engine-rpc-enabled        \
              --engine-jwt-secret=/tmp/jwtsecret
            ```

        === "Goerli/Prater"
            ```sh
            besu \
              --network=goerli            \
              --rpc-http-enabled=true     \
              --rpc-http-host=0.0.0.0     \
              --rpc-http-cors-origins="*" \
              --rpc-ws-enabled=true       \
              --rpc-ws-host=0.0.0.0       \
              --host-allowlist="*"        \
              --engine-host-allowlist="*" \
              --engine-rpc-enabled        \
              --engine-jwt-secret=/tmp/jwtsecret
            ```

    1. Leave the clients running to synchronize data. Besu starts its synchronization after Nimbus is mostly synced. The synchronization process may take hours to days, depending on your hardware performance. 

=== "Erigon"
        
    1. Download and install Erigon following the guide in the [Erigon README file :octicons-tab-external-16:](https://github.com/ledgerwatch/erigon#erigon){:target="_blank"}.
    
    1. Use the `openssl rand` command to create a `jwtsecret` file and store it in the `/tmp` directory. This file is a JSON web token for the clients to authenticate each other.
    ```bash
    openssl rand -hex 32 | tr -d "\n" > "/tmp/jwtsecret"
    ```

    1. Connect Erigon to Nimbus. With the following command, you can start Erigon, enable JSON RPC and specify the path to the `jwtsecret` file. Erigon accepts connections from the localhost interface `127.0.0.1`, with the default RPC port `8551`. Also, Erigon generates a JSON web token (the `jwtsecret` file) for the clients to authenticate each other. 
    
        === "Mainnet"
            ```sh
            ./build/bin/erigon \
              --chain mainnet \
              --externalcl \
              --http --http.api=engine,eth,web3,net \
              --authrpc.jwtsecret=/tmp/jwtsecret
            ```
        === "Goerli/Prater"
            ```sh
            ./build/bin/erigon \
              --chain goerli \
              --externalcl \
              --http --http.api=engine,eth,web3,net \
              --authrpc.jwtsecret=/tmp/jwtsecret
            ```

    1. Leave the clients running to synchronize data. Nethermind starts its synchronization after Nimbus is mostly synced. The synchronization process may take hours to days, depending on your hardware performance.    

=== "Geth"

    1. Download and install Geth following the guide in the [Geth documentation :octicons-tab-external-16:](https://geth.ethereum.org/docs/){:target="_blank"}.
    
    1. Use the `openssl rand` command to create a `jwtsecret` file and store it in the `/tmp` directory. This file is a JSON web token for the clients to authenticate each other.
    ```bash
    openssl rand -hex 32 | tr -d "\n" > "/tmp/jwtsecret"
    ```
    
    1. Connect Geth to Nimbus. With the following command, you can start Geth, expose an RPC port for Nimbus and pass the path to the `jwtsecret` file. Geth accepts connections from the localhost interface `127.0.0.1`, with the default RPC port `8551`.
        
        === "Mainnet"
            ```sh
            geth \
              --ws \
              --authrpc.addr localhost \
              --authrpc.port 8551 \
              --authrpc.vhosts localhost \
              --authrpc.jwtsecret /tmp/jwtsecret
            ```
        === "Goerli/Prater"
            ```sh
            geth \
              --goerli \
              --ws \
              --authrpc.addr localhost \
              --authrpc.port 8551 \
              --authrpc.vhosts localhost \
              --authrpc.jwtsecret /tmp/jwtsecret
            ```

    1. Leave the clients running to synchronize data. Geth starts its synchronization after Nimbus is mostly synced. The synchronization process may take hours to days, depending on your hardware performance.  

=== "Nethermind"

    1. Download and install Nethermind following the guide in the [Nethermind documentation :octicons-tab-external-16:](https://docs.nethermind.io/nethermind/){:target="_blank"}.

    1. Use the `openssl rand` command to create a `jwtsecret` file and store it in the `/tmp` directory. This file is a JSON web token for the clients to authenticate each other.
    ```bash
    openssl rand -hex 32 | tr -d "\n" > "/tmp/jwtsecret"
    ```

    1. Allow Nethermind to connect to Nimbus. With the following command, you can start Nethermind, expose an RPC port (by default, the port is `8551`) for Nimbus, and pass the path to the `jwtsecret` file.
    
        === "Mainnet"
            ```sh    
            ./Nethermind.Runner \
                --config mainnet \
                --JsonRpc.EnginePort=8551 \
                --JsonRpc.JwtSecretFile="/tmp/jwtsecret"
            ```
        === "Goerli/Prater"
            ```sh
            ./Nethermind.Runner \
                --config goerli \
                --JsonRpc.EnginePort=8551 \
                --JsonRpc.JwtSecretFile="/tmp/jwtsecret"
            ```

    1. Leave the clients running to synchronize data. Nethermind starts its synchronization after Nimbus is mostly synced. The synchronization process may take hours to days, depending on your hardware performance.


## Create a validator

If you want to stake on Ethereum or validate transactions for the Ethereum network, you need to create one or more validators. If you only plan to use the Ethereum node for synchronizing the blockchain data, you don't need to follow the rest of this guide.

1. Enter the nimbus directory using the `cd` command.
```sh
cd nimbus-eth2
```

1. Download the latest [Ethereum staking deposit CLI :octicons-tab-external-16:](https://github.com/ethereum/staking-deposit-cli/releases){:target="_blank"}  with `wget`. In the following command, replace `<version_number>` with the version number of the latest release, and replace `<name_of_the_release_package>` with the name of the package to download. Choose the file that matches your Ubuntu architecture.
```sh
wget https://github.com/ethereum/staking-deposit-cli/releases/download/<version_number>/<name_of_the_release_package>
```

    For example,
    ```sh
    wget https://github.com/ethereum/staking-deposit-cli/releases/download/v2.3.0/staking_deposit-cli-76ed782-linux-arm64.tar.gz 
    ```

1. Unpack the `tar.gz` file with the `tar xvf` command. In the following command, replace `<name_of_the_release_package>` with the name of the package you downloaded.
```sh
tar xvf <name_of_the_release_package> --strip-components 2
```

    For example,
    ```sh
    tar xvf staking_deposit-cli-9ab0b05-linux-amd64.tar.gz --strip-components 2
    ```

1. Prepare a safe environment for running the deposit CLI. When you use the deposit CLI to generate validator keys that allow validator actions, you need a safe environment to avoid risks such as key leakage.

    One option is to follow [Ubuntu's instructions :octicons-tab-external-16:](https://ubuntu.com/tutorials/try-ubuntu-before-you-install#1-getting-started){:target="_blank"} to set up a live Ubuntu from a USB stick. Another option is to copy the deposit CLI to a machine that has never been connected to the internet and run it there.

1. Copy the deposit CLI (the executable file with the name `deposit`) to the safe environment. For example, you can use a USB stick.

1. Disable all internet connections during this process to prevent security risks. Open the terminal and run the following command to create a validator and associated keys using the deposit CLI.

    === "Mainnet"
        ```sh
        ./deposit new-mnemonic --chain mainnet
        ```

    === "Goerli/Prater"
        ```sh
        ./deposit new-mnemonic --chain prater
        ```

    !!! Caution
        Backup your mnemonic and password in a safe place and do not share them with anyone. You need the mnemonic and the password to operate the validator and access your funds. If you lose them, it's impossible to recover.
    After running the command, follow the instructions on the screen to create these credentials and files for your validator:

    | Item | Format | Location | Usage |
    |-----|---------|----------|----|
    | Password for the validator keystore | Charaters and symbols you choose |Keep it by yourself | Access validator keystore |
    | Mnemonic| 12 words generated randomly | Keep it by yourself | Generate withdrawal keys, access funds in the validator |
    | Validator keystore| `keystore-[..].json` | `validator_keys` folder |Authorize validator actions |
    | Deposit data|`deposit_data-[timestamp].json` | `validator_keys` folder |Upload it when you stake deposit in the next step |

## Activate the validator

After your execution client and consensus client are fully synced, you can activate your validator. You might receive inactivity penalties if your validator is active before your clients are ready.

1. Move the `validator_keys` folder containing the validator keystore and the deposit data to the `nimbus-eth2` directory in the computer running the clients.

1. Import validator keys into Nimbus data directory by running the following command. Replace `<username>` with your Ubuntu username.
    
    === "Mainnet"
        ```sh
        sudo /home/<username>/nimbus-eth2/build/nimbus_beacon_node deposits import --data-dir=/var/lib/nimbus/shared_mainnet_0 /home/<username>/nimbus-eth2/validator_keys
        ```

    === "Goerli/Prater"
        ```sh
        sudo /home/<username>/nimbus-eth2/build/nimbus_beacon_node deposits import --data-dir=/var/lib/nimbus/shared_prater_0 /home/<username>/nimbus-eth2/validator_keys
        ```

    After importing the keys, you can see this message:

    ```
    NOT 2022-07-19 17:36:37.578+02:00 Keystore imported
    ```

1. Choose an address to receive validator rewards. Press `Ctrl-c` to stop Nimbus if it's running. In the below command, replace `<fee_recipient_address>` with the wallet address to receive rewards, then run it to restart Nimbus and allow your update to take effect.

    === "Mainnet"
        ```sh
        ./run-mainnet-beacon-node.sh \
          --web3-url=http://127.0.0.1:8551 \
          --suggested-fee-recipient=<fee_recipient_address>
        ```
    === "Goerli/Prater"
        ```sh
        ./run-prater-beacon-node.sh \
          --web3-url=http://127.0.0.1:8551 \
          --suggested-fee-recipient=<fee_recipient_address>
        ```

1. Deposit 32 ETH into the deposit contract via the Ethereum Launchpad page for each validator. Here are some tips for performing the deposit.
    
    === "Mainnet"
        - Visit the [Mainnet lanuchpad page :octicons-tab-external-16:](https://launchpad.ethereum.org/en/){:target="_blank"} and follow the instructions.
        - Double-check the contract address you deposit into. The correct deposit contract address is `0x00000000219ab540356cBB839Cbe05303d7705Fa`. View details of the deposit contract on [Etherscan :octicons-tab-external-16:](https://etherscan.io/address/0x00000000219ab540356cbb839cbe05303d7705fa){:target="_blank"}.
        - Do not deposit directly to the deposit contract address. Only use the launchpad page to deposit.
        - You can check the status of your validator by searching for your wallet address on [beaconcha.in :octicons-tab-external-16:](https://beaconcha.in/){:target="_blank"}.
        
    === "Goerli/Prater"
        - Visit the [testnet lanuchpad page :octicons-tab-external-16:](https://goerli.launchpad.ethstaker.cc/en/){:target="_blank"} and follow the instructions.
        - If you don't have Goerli testnet ETH, follow the instructions in the #cheap-goerli-validator channel of the [EthStaker Discord :octicons-tab-external-16:](https://discord.io/ethstaker){:target="_blank"}. You can have the access to this channel after 2-3 days joining the Discord server. 
        - Do not deposit directly to the deposit contract address. Only use the launchpad page to deposit.
        - You can check the status of your validator by searching for your wallet address on [goerli.beaconcha.in :octicons-tab-external-16:](https://goerli.beaconcha.in/){:target="_blank"}.

    Once you send off the deposit transaction, your validator is put in an activation queue based on the deposit time. Getting through the queue may take a few hours or days, you can leave your clients and validator running. As soon as your validator becomes active, it begins validating automatically.
