# Run an execution client

In order to run a beacon node, you need to also be running an execution client - one for each beacon node.

Nimbus has been tested all major execution clients - see the [execution client comparison](https://ethereum.org/en/developers/docs/nodes-and-clients/#execution-clients) for more information.

!!! warning
    You need to run your own execution client - relying on third-party services such as Infura, Alchemy and Pocket will not be possible.

!!! info
    Syncing an execution client may take hours or even days, depending on your hardware! The backup providers will be synced only when the primary becomes unavailable, which may lead to a small gap in validation duties - this limitation may be lifted in future versions.

## Steps

### 1. Install execution client

Select an execution client and install it, configuring it such that that WebSockets are enabled and a JWT secret file is created.

=== "Nimbus"

    In parallel to `nimbus-eth2`, we are working hard on the [Nimbus execution client](https://github.com/status-im/nimbus-eth1). While this is very much a project in development (i.e. not yet ready for public consumption), we welcome you to experiment with it.

=== "Geth"

    #### 1. Install Geth

    See the [Installing Geth](https://geth.ethereum.org/docs/install-and-build/installing-geth) for instructions on installing Geth.

    #### 2. Start Geth

    Once you have geth installed, make sure to enable the JSON-RPC WebSocket interface when running geth, along with the options for creating an [autheticated RPC endpoint](https://geth.ethereum.org/docs/interface/consensus-clients):

    === "Mainnet"
        ```
        geth --ws --authrpc.addr localhost --authrpc.port 8551 --authrpc.vhosts localhost --authrpc.jwtsecret /tmp/jwtsecret
        ```

    === "Goerli"
        ```
        geth --goerli --ws --authrpc.addr localhost --authrpc.port 8551 --authrpc.vhosts localhost --authrpc.jwtsecret /tmp/jwtsecret
        ```

    !!! note
        The `--ws` flag allows Nimbus to connect using WebSockets.

    #### 3. Leave Geth running

    Let it syns - it may take anywhere between a few hours and a couple of days.

    You'll know Geth has finished syncing, when you start seeing logs that look like the following:

    ```
    INFO [05-29|01:16:05] Imported new chain segment               blocks=1 txs=3   mgas=0.065  elapsed=5.885ms   mgasps=11.038  number=3785445 hash=553d9e…fc4547
    INFO [05-29|01:16:10] Imported new chain segment               blocks=1 txs=0   mgas=0.000  elapsed=5.447ms   mgasps=0.000   number=3785446 hash=5e3e7d…bd4afd
    INFO [05-29|01:16:10] Imported new chain segment               blocks=1 txs=1   mgas=0.021  elapsed=7.382ms   mgasps=2.845   number=3785447 hash=39986c…dd2a01
    INFO [05-29|01:16:14] Imported new chain segment               blocks=1 txs=11  mgas=1.135  elapsed=22.281ms  mgasps=50.943  number=3785444 hash=277bb9…623d8c
    ```

    Geth accepts connections from the localhost interface (`127.0.0.1`), with default authenticated RPC port `8551`. This means that your default Web3 provider URL should be: `ws://127.0.0.1:8551`

=== "Nethermind"

    See the [Getting started](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/getting-started) guide to set up Nethermind.

    Make sure to enable the [JSON-RPC](https://docs.nethermind.io/nethermind/first-steps-with-nethermind/running-nethermind-post-merge#jsonrpc-configuration-module) interface over WebSockets, and pass `--JsonRpc.JwtSecretFile=/tmp/jwtsecret` to select a JWT secret file location.

=== "Besu"

    See the [Besu documentation](https://besu.hyperledger.org/en/stable/) for instructions on setting up Besu.

    Make sure to enable the [JSON-RPC](https://besu.hyperledger.org/en/stable/HowTo/Interact/APIs/Using-JSON-RPC-API/) WebSocket interface and store the JWT token in `/tmp/jwtsecret`.

=== "Erigon"

    See the [Erigon README](https://github.com/ledgerwatch/erigon#getting-started) for instructions on setting up Erigon.

    Make sure to enable the [JSON-RPC](https://github.com/ledgerwatch/erigon#beacon-chain-consensus-layer) WebSocket interface and use `--authrpc.jwtsecret=/tmp/jwtsecret` to set a path to the JWT token file.

### 2. Leave the execution client running

The execution client will be syncing the chain through the merge transition block. Once it reaches this point, it will wait for the beacon node to provide further sync instructions.

It is safe to start the beacon node even if the execution client is not yet fully synced and vice versa.

### 3. Pass the URL and JWT secret to Nimbus

The `--web3-url` option informs the beacon node how to connect to the execution client - both `http://` and `ws://` URL:s are supported.

Once started, the execution client will create a file containing a JWT secret token. The token file is needed for Nimbus to authenticate itself with the execution client and perform trusted operations. You will need to pass the path to the token file to Nimbus together with the web3 URL.

=== "Mainnet"
    ```sh
    ./run-mainnet-beacon-node.sh \
      --web3-url=ws://127.0.0.1:8551 \
      --jwt-secret=/tmp/jwtsecret
    ```

=== "Prater"
    ```sh
    ./run-prater-beacon-node.sh \
      --web3-url=ws://127.0.0.1:8551 \
      --jwt-secret=/tmp/jwtsecret
    ```

!!! tip
    You can pass one or more `--web3-url` parameters to the node as long as they share JWT secret. Any additional web3 url:s will be used for backup, should the first one become unavailable:

    ```sh
    ./run-mainnet-beacon-node.sh \
      --web3-url=ws://127.0.0.1:8551 \
      --web3-url=http://other:8551 \
      --jwt-secret=/tmp/jwtsecret
    ```
