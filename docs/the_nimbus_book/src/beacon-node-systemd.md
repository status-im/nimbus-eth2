# Set up a systemd service

This page will take you through how to set up a `systemd` service for your beacon node.

Systemd is used in order to have a command or program run when your device boots (i.e. add it as a service). Once this is done, you can start/stop enable/disable from the linux prompt.

> [`systemd`](https://www.freedesktop.org/wiki/Software/systemd/) is a service manager designed specifically for Linux. There is no port to Mac OS. You can get more information from [https://www.raspberrypi.org/documentation/linux/usage/systemd.md](https://www.raspberrypi.org/documentation/linux/usage/systemd.md)  or  [https://fedoramagazine.org/what-is-an-init-system/](https://www.raspberrypi.org/documentation/linux/usage/systemd.md)

### 1. Create a systemd service

> ⚠️  If you wish to run the service with metrics enabled, you'll need to replace `--metrics:off` with `--metrics:on` in the service file below. See [here](./metrics-pretty-pictures.md) for more on metrics.

Create a `systemd` service unit file -- `nimbus-eth2-pyrmont.service` -- and save it in `/etc/systemd/system/`.

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
  --metrics:off
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


### 2. Notify systemd of the newly added service

```console
sudo systemctl daemon-reload
```

### 3. Start the service

```console
sudo systemctl enable nimbus-eth2-pyrmont --now
```
