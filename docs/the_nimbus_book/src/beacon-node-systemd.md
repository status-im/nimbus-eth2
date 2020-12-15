# Set up a systemd service

This page will take you through how to set up a `systemd` service for your beacon node.
> [`systemd`](https://www.freedesktop.org/wiki/Software/systemd/) is a service manager designed specifically for Linux. There is no port to Mac OS.

## Prerequisites

NBC's [external dependencies](./install.md#external-dependencies).

### 1. Clone repository

If you haven't done so already, clone the [nimbus-eth2](https://github.com/status-im/nimbus-eth2) repository.

```console
git clone https://github.com/status-im/nimbus-eth2.git
```

### 2. Build repository

Move into the directory and build the beacon node.

```console
cd nimbus-eth2
make nimbus_beacon_node
```


The resulting binaries should appear in `nimbus-eth2/build/nimbus_beacon_node`.

### 3. Create a systemd service unit file

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


### 4. Notify systemd of the newly added service

```console
sudo systemctl daemon-reload
```

### 5. Start the service

```console
sudo systemctl enable nbc --now
```

