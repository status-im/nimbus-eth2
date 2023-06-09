# Beacon API

Nimbus exposes an **extremely fast** implementation of the standard [Beacon API](https://ethereum.github.io/beacon-APIs/).
The API allows you to use Nimbus together with third-party tooling such as validator clients, block explorers, as well as your own monitoring infrastructure.

The Beacon API is a `REST` interface accessed via `http`.
If you wish to expose the beacon node to the public internet, it is recommended to use a proxy such as `nginx` to provide caching and SSL support.

!!! warning
    If you are running validators with your beacon node, do not expose the REST API to the public internet or use the same beacon node for deep historical queries: doing so may negatively affect validator performance.

## Test your tooling against our servers

 The API is available from:

* `http://testing.mainnet.beacon-api.nimbus.team/`
* `http://unstable.mainnet.beacon-api.nimbus.team/`
* `http://unstable.prater.beacon-api.nimbus.team/`

You can make requests as follows (here we are requesting the version the Nimbus software version of the node in question):

=== "Mainnet testing branch"
    ```
    curl -X GET http://testing.mainnet.beacon-api.nimbus.team/eth/v1/node/version
    ```

=== "Mainnet unstable branch"
    ```
    curl -X GET http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/node/version
    ```

=== "Prater unstable branch"
    ```
    curl -X GET  http://unstable.prater.beacon-api.nimbus.team/eth/v1/node/version
    ```

The test endpoints are part of pre-release testing and run an unstable version of Nimbus.
We welcome reports about any problems you might have with them.

They may also be unresponsive at times: **please do not rely on them for validation**.
We may also disable them at any time without warning.


## Configure your node to run a local REST server

By default, the REST interface is disabled.
To enable it, start the beacon node with the `--rest` option:

```
./run-mainnet-beacon-node.sh --rest
```

Then access the API from `http://localhost:5052/`.
For example, to get the version of the Nimbus software your node is running:

```
curl -X GET http://localhost:5052/eth/v1/node/version
```

By default, only connections from the same machine are entertained.
The port and listening address can be further configured through the options `--rest-port` and `--rest-address`.

!!! warning
    If you are using a validator client with a Nimbus beacon node, and running a Nimbus version prior to `v1.5.5`, then you will need to launch the node with the `--subscribe-all-subnets` option enabled (in addition to the `--rest` option).

## Some useful commands

### Standard endpoints

While these are all well documented in the [official docs](https://ethereum.github.io/beacon-APIs/), here are a handful of simple examples to get you started:

#### Genesis

Retrieve details of the chain's genesis which can be used to identify chain.

=== "With our mainnet testing server"
    ```
    curl -X GET http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/beacon/genesis
    ```

=== "With your own local server"
    ```
    curl -X GET http://localhost:5052/eth/v1/beacon/genesis
    ```

#### Deposit contract

Get deposit contract address (retrieve Eth1 deposit contract address and chain ID).

=== "With our mainnet testing server"
    ```
    curl -X GET http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/config/deposit_contract
    ```

=== "With your own local server"
    ```
    curl -X GET http://localhost:5052/eth/v1/config/deposit_contract
    ```


#### Peer count

Get peer count:

=== "With our mainnet testing server"
    ```
    curl -X GET http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/node/peer_count
    ```

=== "With your own local server"
    ```
    curl -X GET http://localhost:5052/eth/v1/node/peer_count
    ```


#### Syncing status

Get node syncing status (requests the beacon node to describe if it's currently syncing or not, and if it is, what block it is up to)

=== "With our mainnet testing server"
    ```
    curl -X GET http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/node/syncing
    ```

=== "With your own local server"
    ```
    curl -X GET http://localhost:5052/eth/v1/node/syncing
    ```

#### Fork schedule

Get scheduled upcoming forks (retrieve all forks, past present and future, of which this node is aware)

=== "With our mainnet testing server"
    ```
    curl -X GET http://unstable.mainnet.beacon-api.nimbus.team/eth/v1/config/fork_schedule
    ```

=== "With your own local server"
    ```
    curl -X GET http://localhost:5052/eth/v1/config/fork_schedule
    ```


### Nimbus specific endpoints

In addition to supporting the standard endpoints, Nimbus has a set of specific endpoints which augment the standard API.


#### Check Graffiti String


=== "With our mainnet testing server"
    ```
    curl -X GET http://testing.mainnet.beacon-api.nimbus.team/nimbus/v1/graffiti
    ```

=== "With your own local server"
    ```
    curl -X GET http://localhost:5052/nimbus/v1/graffiti
    ```

#### Set Graffiti String

=== "With your own local server"
    ```
    curl -X POST http://localhost:5052/nimbus/v1/graffiti -H  "Content-Type: text/plain" -d "new graffiti"
    ```

#### Set Log Level

*TBA*



## Specification

- The complete API specification is well documented [here](https://ethereum.github.io/beacon-APIs/)

- See the repository Readme [here](https://github.com/ethereum/beacon-APIs)

