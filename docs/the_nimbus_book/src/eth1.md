# Run an execution client

In order to perform validation duties, you **must have** an execution client running — at least one for each beacon node.
Relying on third-party services such as Infura, Alchemy and Pocket is no longer possible.
Sharing the same execution client between multiple beacon nodes is not supported.

Nimbus has been tested with all major execution clients.
See the [execution client comparison](https://ethereum.org/en/developers/docs/nodes-and-clients/#execution-clients) for more information.

!!! info
    Syncing an execution client **may take hours or even days**, depending on your hardware!


## Steps

### 1. Install execution client

Select an execution client and install it, configuring it such that that the authenticated JSON-RPC interface is enabled and a JWT secret file is created.

=== "Nimbus"

    In parallel to `nimbus-eth2`, we are working hard on the [Nimbus execution client](https://github.com/status-im/nimbus-eth1).
    While this is very much a project in development (i.e. not yet ready for public consumption), we welcome you to experiment with it.

=== "Geth"

    #### 1. Install Geth

    See the [Installing Geth guide](https://geth.ethereum.org/docs/getting-started/installing-geth) for instructions on installing Geth.

    #### 2. Start Geth

    Once you have geth installed, make sure to enable the [authenticated JSON-RPC interface](https://geth.ethereum.org/docs/getting-started/consensus-clients) when running geth:

    === "Mainnet"
        ```
        geth --authrpc.addr localhost --authrpc.port 8551 --authrpc.vhosts localhost --authrpc.jwtsecret /tmp/jwtsecret
        ```

    === "Holesky"
        ```
        geth --holesky --authrpc.addr localhost --authrpc.port 8551 --authrpc.vhosts localhost --authrpc.jwtsecret /tmp/jwtsecret
        ```

=== "Nethermind"

    See the [Installing Nethermind guide](https://docs.nethermind.io/get-started/installing-nethermind) to set up Nethermind.

    Make sure to enable the [JSON-RPC](https://docs.nethermind.io/interacting/json-rpc-server) interface and pass `--JsonRpc.JwtSecretFile=/tmp/jwtsecret` to select a JWT secret file location.

=== "Besu"

    See the [Besu documentation](https://besu.hyperledger.org/public-networks/get-started/install) for instructions on setting up Besu.

    Make sure to enable the [JSON-RPC](https://besu.hyperledger.org/public-networks/how-to/use-besu-api/json-rpc) interface and store the JWT token in `/tmp/jwtsecret`.

=== "Erigon"

    See the [Erigon README](https://github.com/ledgerwatch/erigon#getting-started) for instructions on setting up Erigon.

    Make sure to enable the [JSON-RPC](https://github.com/ledgerwatch/erigon#beacon-chain-consensus-layer) interface and use `--authrpc.jwtsecret=/tmp/jwtsecret` to set a path to the JWT token file.

### 2. Leave the execution client running

The execution client needs to be running at all times in order for the beacon node to be able to support validators.
It will start its syncing process as soon as the beacon node connects to it.
Once both are synced, they will continue to work in tandem to validate the latest Ethereum state.

It is safe to start the beacon node even if the execution client is not yet fully synced, and vice versa.

### 3. Pass the URL and JWT secret to Nimbus

The `--el` option informs the beacon node how to connect to the execution client — both `http://` and `ws://` URLs are supported.

!!! info
    By default, the execution client accepts connections on the localhost interface (`127.0.0.1`), with default authenticated RPC port `8551`.
    When the `--el` option is not explicitly specified, Nimbus will assume that the execution client is running on the same machine with such default settings.

Once started, the execution client will create a file containing a JWT secret token.
The token file is needed for Nimbus to authenticate itself with the execution client and perform trusted operations.
You will need to pass the path to the token file to Nimbus together with the web3 URL.

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh \
      --el=http://127.0.0.1:8551 \
      --jwt-secret=/tmp/jwtsecret
    ```

=== "Holesky"
    ```sh
    ./run-holesky-beacon-node.sh \
      --el=http://127.0.0.1:8551 \
      --jwt-secret=/tmp/jwtsecret
    ```

!!! info
    When the `--jwt-secret` option is not specified and the execution client is running on the same machine under default setting, Nimbus may be able to connect successfully to it by using the default secret value `0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3`.
    This is a [proposed standard protocol](https://github.com/ethereum/execution-apis/pull/302) that aims to simplify the required user configuration, but it's not yet adopted by all execution clients.




## Upgrade execution client

=== "Nimbus"

    In the `nimbus-eth1` directory, run the following commands:
    ```
    git pull
    make -j4 update
    make -j4 nimbus
    ```


=== "Geth"

    Following [Geth update instructions](https://geth.ethereum.org/docs/faq#how-to-update-geth), to update Geth you need to:
    

    1. stop the node, 
    2. download the latest release (follow [installation instructions](https://geth.ethereum.org/docs/getting-started/installing-geth)),
    3. restart the node.


=== "Nethermind"

    There are several ways of updating Nethermind, depending on the installation method.
    Follow [Nethermind upgrade instructions](https://docs.nethermind.io/faq/#how-do-i-upgrade-my-node).


=== "Besu"

    Follow [Besu upgrade instructions](https://besu.hyperledger.org/public-networks/how-to/upgrade-node).




## Advanced setups

### Running multiple execution clients

You can increase the resilience of your setup and eliminate any downtime during upgrade procedure of the execution client software by allowing your beacon node to manage multiple execution clients.
To enable this mode, just specify multiple URLs through the `--el` option when starting your beacon node:

```sh
./run-mainnet-beacon-node.sh \
  --el=http://127.0.0.1:8551 \
  --el=ws://other:8551 \
  --jwt-secret=/tmp/jwtsecret
```

!!! tip
    You can use a different secret for each connection by specifying `jwt-secret` or `jwt-secret-file` as a query parameter in the anchor section of the URL (e.g. `http://127.0.0.1:8551/#jwt-secret=0x12345...` or `http://127.0.0.1:8551/#jwt-secret-file=/tmp/jwtsecret`).
    If you use a [TOML config file](./options.md#configuration-files), you can also use the following, more natural, syntax:

    ```toml
    data-dir = "my-data-dir"
    rest = true
    ...

    [[el]]
    url = "http://127.0.0.1:8551"
    jwt-secret-file="/path/to/jwt/file"

    [[el]]
    url = "http://192.168.1.2:8551"
    jwt-secret = ""
    ```

As long as any of execution clients remains operational and fully synced, Nimbus will keep performing all validator duties.

!!! tip
    To carry out an upgrade procedure without any downtime, just restart the execution clients one by one, waiting for each instance to re-sync before moving to the next one.

If you use this mode with different execution client implementations, Nimbus will act as an execution layer consensus violation detector, preventing the publishing of blocks that may trigger a catastrophic partitioning in the network.
