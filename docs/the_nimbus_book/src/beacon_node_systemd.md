# Setting up a systemd service

This guide will take you through how to set up a `systemd` service for your beacon node.
> [`systemd`](https://www.freedesktop.org/wiki/Software/systemd/) is a service manager designed specifically for Linux. There is no port to Mac OS.

## Prerequisites

NBC's [external dependencies](./install.md#external-dependencies) and a working [Go](https://golang.org/doc/install) installation (v1.11 or later).

### 1. Clone repositories

Clone the [nim-beacon-chain](https://github.com/status-im/nim-beacon-chain) and [eth2stats](https://github.com/Alethio/eth2stats-client) repositories in the same directory (so that both repositories are adjacent to each other).

```console
git clone https://github.com/status-im/nim-beacon-chain.git
git clone https://github.com/Alethio/eth2stats-client.git
```

### 2. Build repositories

Build both repositories by following their respective build instructions. 

*nim-beacon-chain*
```console
cd nim-beacon-chain
make beacon_node
```


*eth2stats*
```console
cd eth2stats-client
make build
```

The resulting binaries should appear in `nim-beacon-chain/build/beacon_node` and `eth2stats-client/eth2stats-client`, respectively.

### 3. Register your node

Add your node to eth2stats and run a data collector app that connects to your beacon chain client.

```
./eth2stats-client run \
--eth2stats.node-name="<NODE_NAME>" \
--data.folder ~/.eth2stats/data \
--eth2stats.addr="grpc.medalla.eth2stats.io:443" --eth2stats.tls=true \
--beacon.type="nimbus" \
--beacon.addr="http://localhost:9190" \
--beacon.metrics-addr="http://localhost:8008/metrics"
```

Replace `<NODE_NAME>` with the name you wish to identify your node with on [eth2stats](https://eth2stats.io/).

### 4. Create an executable script

Create an executable script, `run_nimbus_node.sh`, and place it adjacent to the repositories you cloned in step 1 (same directory level).

```bash
#!/bin/bash

set +e

trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

cd $(dirname "$0")
cd nim-beacon-chain

NETWORK=$1
NODE_NAME=${NODE_NAME:-$(whoami)}

if [[ "$2" == "" ]]; then
  NODE_ID=0
else
  NODE_ID=$2
  NODE_NAME=$NODE_NAME-$2
fi

let METRICS_PORT=8008+${NODE_ID}
let RPC_PORT=9190+${NODE_ID}

mkdir -p /tmp/e2s-$ID
../eth2stats-client/eth2stats-client run \
  --data.folder=/tmp/${NODE_NAME} \
  --eth2stats.node-name="${NODE_NAME}" \
  --eth2stats.addr="grpc.${NETWORK}.eth2stats.io:443" --eth2stats.tls=true \
  --beacon.type="nimbus" \
  --beacon.addr="http://localhost:$RPC_PORT" \
  --beacon.metrics-addr="http://localhost:$METRICS_PORT/metrics" > /tmp/ethstats.$NODE_NAME.log 2>&1 &

make NIMFLAGS="-d:insecure" NODE_ID=$NODE_ID ${NETWORK}
```

> Tip: don't forget to mark the script as executable by running `chmod +x` on it.

### 5. Create a systemd service unit file

Create a `systemd` service unit file, `nbc.service`, and save it in `/etc/systemd/system/`.

```txt
[Unit]
Description=Nimbus beacon node

[Service]
ExecStart=<BASE-DIRECTORY>/run_nimbus_node.sh medalla
User=<USERNAME>
Group=<USERNAME>
Restart=always
RuntimeMaxSec=10800

[Install]
WantedBy=default.target

```

Replace:

`<BASE-DIRECTORY>` with the location of the repository in which you performed the `git clone` command in step 1.

`<USERNAME>` with the username of the system user responsible for running the launched processes.

### 6. Notify systemd of the newly added service

```console
sudo systemctl daemon-reload
```

### 7. Start the nim beacon chain service

```console
sudo systemctl enable nbc --now
```
