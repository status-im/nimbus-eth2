# Set up a systemd service

This page will take you through how to set up a `systemd` service for your beacon node.
> [`systemd`](https://www.freedesktop.org/wiki/Software/systemd/) is a service manager designed specifically for Linux. There is no port to Mac OS.

## Prerequisites

NBC's [external dependencies](./install.md#external-dependencies) and a working [Go](https://golang.org/doc/install) installation (v1.11 or later).

### 1. Clone repositories

Clone the [nimbus-eth2](https://github.com/status-im/nimbus-eth2) and [eth2stats](https://github.com/Alethio/eth2stats-client) repositories in the same directory (so that both repositories are adjacent to each other).

```console
git clone https://github.com/status-im/nimbus-eth2.git
git clone https://github.com/Alethio/eth2stats-client.git
```

### 2. Build repositories

Build both repositories by following their respective build instructions. 

*nimbus-eth2*
```console
cd nimbus-eth2
make nimbus_beacon_node
```


*eth2stats*
```console
cd eth2stats-client
make build
```

The resulting binaries should appear in `nimbus-eth2/build/nimbus_beacon_node` and `eth2stats-client/eth2stats-client`, respectively.

### 3. Create a systemd service unit file for the Nimbus beacon node service

Create a `systemd` service unit file -- `nbc.service` -- and save it in `/etc/systemd/system/`.

```txt
[Unit]
Description=Nimbus beacon node

[Service]
WorkingDirectory=<BASE-DIRECTORY>
ExecStart=<BASE-DIRECTORY>/build/nimbus_beacon_node \
  --non-interactive \
  --network=pyrmont \
  --data-dir=build/data/shared_pyrmont_0 \
  --web3-url=<WEB3-URL> \
  --rpc:on \
  --metrics:on
User=<USERNAME>
Group=<USERNAME>
Restart=always

[Install]
WantedBy=default.target
```

Replace:

`<BASE-DIRECTORY>` with the location of the repository in which you performed the `git clone` command in step 1.

`<USERNAME>` with the username of the system user responsible for running the launched processes.

`<WEB3-URL>` with the WebSocket JSON-RPC URL that you are planning to use.

### 4. Create a systemd service unit file for the Eth2Stats client

Create a `systemd` service unit file -- `eth2stata.service` -- and save it in `/etc/systemd/system/`.

```txt
[Unit]
Description=Eth2Stats Client

[Service]
ExecStart=<BASE-DIRECTORY>/eth2stats-client run \
  --data.folder=<BASE-DIRECTORY>/data \
  --eth2stats.node-name="<NODE-NAME>" \
  --eth2stats.addr="grpc.pyrmont.eth2.wtf:8080" --eth2stats.tls=false \
  --beacon.type="nimbus" \
  --beacon.addr="http://localhost:9190" \
  --beacon.metrics-addr="http://localhost:8008/metrics"
User=<USERNAME>
Group=<USERNAME>
Restart=always

[Install]
WantedBy=default.target
```

Replace:

`<BASE-DIRECTORY>` with the location of the repository in which you performed the `git clone` command in step 1.

`<USERNAME>` with the username of the system user responsible for running the launched processes.

`<NODE-NAME>` with the name of your node on [https://pyrmont.eth2.wtf/](https://pyrmont.eth2.wtf/).

### 5. Notify systemd of the newly added services

```console
sudo systemctl daemon-reload
```

### 6. Start the services

```console
sudo systemctl enable nbc --now
sudo systemctl enable eth2stats --now
```

