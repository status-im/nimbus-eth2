# Prater testnet

`prater`, also known as `goerli`, is the current long-running merge testnet. It provides an opportunity to verify your setup works as expected through the proof-of-stake transition and in a post-merge context as well as to safely practise node operations such as adding and removing validators, migrating between clients, and performing upgrades and backups. If you come across any issues, please [report them here](https://github.com/status-im/nimbus-eth2/issues).

!!! note
    Post-merge, node runners will need to run both a consensus and execution layer client.

# General Preparation

1. Generate the JWT secret with `openssl rand -hex 32 | tr -d "\n" > "/opt/jwtsecret"`. This file needs to be passed to both the execution client and the consensus client.

2. Choose an Ethereum address to receive transaction fees. This ETH will be immediately available, not part of the staking contract.

3. Download the [latest release](./binaries.md) and install it by unpacking the archive.

4. Choose one of Nethermind, Besu, Erigon, or Geth as an execution client, using one of the [compatible versions](https://blog.ethereum.org/2022/07/27/goerli-prater-merge-announcement/#execution-layer). Download, install, and [run it](https://notes.ethereum.org/@launchpad/goerli#Run-an-Execution-Layer-Client).

For example, Nethermind on Goerli can run via:
```sh
cd nethermind/src/Nethermind/Nethermind.Runner
dotnet run -c Release -- --config goerli \
--JsonRpc.Host=0.0.0.0 \
--JsonRpc.JwtSecretFile=/opt/jwtsecret
```

Erigon can be run using:
```sh
./build/bin/erigon --chain=goerli \
--datadir goerli-testnet \
--authrpc.jwtsecret=/opt/jwtsecret \
--http --http.api=engine,net,eth
```

and Besu can be run with the command:
```sh
build/install/besu/bin/besu     \
  --network=goerli              \
  --rpc-http-enabled=true       \
  --rpc-http-host="0.0.0.0"     \
  --rpc-http-cors-origins="*"   \
  --sync-mode="X_SNAP"          \
  --data-storage-format="BONSAI"\
  --Xmerge-support=true         \
  --rpc-ws-host="0.0.0.0"       \
  --host-allowlist="*"          \
  --engine-rpc-enabled=true     \
  --engine-host-allowlist="*"   \
  --engine-jwt-enabled=true     \
  --engine-jwt-secret=/opt/jwtsecret
```

# Sync the beacon node and execution client

5. [Start syncing](./start-syncing.md) the node consisting of Nimbus and chosen execution client, for example by running:
```sh
nimbus-eth2/build/nimbus_beacon_node \
    --network=goerli \
    --web3-url=http://127.0.0.1:8551 \
    --rest \
    --metrics \
    --jwt-secret="/opt/jwtsecret" \
    --suggested-fee-recipient=<Enter-eth-address-here>
```

One might consider here to [set up a systemd service](./beacon-node-systemd.md) to ensure this runs automatically, including after restarts.

# Begin validating

6. Once this Goerli/Prater node is [completely synced](./keep-an-eye.md#keep-track-of-your-syncing-progress), use the [Prater launchpad](https://prater.launchpad.ethereum.org/en/) to obtain Goerli/Prater validators with [Goerli ETH](./goerli-eth.md). It might require some time before these enter and are activated on the beacon chain. If one does this before the node which will attest and propose using those validators has synced, one might miss attestations and block proposals.

7. [Import the validator keys](./keys.md) you receive into Nimbus.

8. [Start validating](./connect-eth2.md) with the imported keys.

## Useful resources

- Goerli/Prater [EF launchpad notes](https://notes.ethereum.org/@launchpad/goerli): how to run a node; contains instructions for how to build Nimbus from source for this purpose

- Goerli/Prater consensus layer [beacon chain explorer](https://prater.beaconcha.in/)

- Goerli/Prater execution layer [blockchain explorer](https://goerli.etherscan.io/)

- Goerli/Prater [landing page](https://goerli.net/): view block explorers, request funds from the faucet, and connect to a JSON RPC endpoint.
