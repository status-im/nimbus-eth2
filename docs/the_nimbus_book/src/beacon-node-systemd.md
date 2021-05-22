# Set up a systemd service

This page will take you through how to set up a `systemd` service for your beacon node.

Systemd is used in order to have a command or program run when your device boots (i.e. add it as a service). Once this is done, you can start/stop enable/disable from the linux prompt.

> [`systemd`](https://www.freedesktop.org/wiki/Software/systemd/) is a service manager designed specifically for Linux. There is no port to Mac OS. You can get more information from [https://www.raspberrypi.org/documentation/linux/usage/systemd.md](https://www.raspberrypi.org/documentation/linux/usage/systemd.md)  or  [https://fedoramagazine.org/what-is-an-init-system/](https://www.raspberrypi.org/documentation/linux/usage/systemd.md)

### 1. Create a systemd service

> ⚠️  If you wish to run the service with metrics enabled, you'll need to replace `--metrics:off` with `--metrics:on` in the service file below. See [here](./metrics-pretty-pictures.md) for more on metrics.

Create a `systemd` service unit file -- `nimbus-eth2-prater.service` -- and save it in `/lib/systemd/system/`.

The contents of the file should look like this:

```txt
[Unit]
Description=Nimbus beacon node

[Service]
WorkingDirectory=<BASE-DIRECTORY>
ExecStart=<BASE-DIRECTORY>/build/nimbus_beacon_node \
  --non-interactive \
  --network=prater \
  --data-dir=build/data/shared_prater_0 \
  --web3-url=<WEB3-URL> \
  --rpc:on \
  --metrics:off
User=<USERNAME>
Group=<USERNAME>
Restart=always

[Install]
WantedBy=default.target
```

Where you should replace:

`<BASE-DIRECTORY>` with the location of the `nimbus-eth2` repository on your device.

`<USERNAME>` with the username of the system user responsible for running the launched processes.

`<WEB3-URL>` with the WebSocket JSON-RPC URL you are planning to use.

> **N.B.** If you're running Nimbus on a Pi, your `<BASE-DIRECTORY>` is `/home/pi/nimbus-eth2/` and your `<USERNAME>` is `pi`

> If you want to run on mainnet, simply replace all instances of `prater` with `mainnet`. If you wish to run on `pyrmont`, replace all instances of `prater` with `pyrmont`.

### 2. Notify systemd of the newly added service

```console
sudo systemctl daemon-reload
```

### 3. Start the service

```console
sudo systemctl enable nimbus-eth2-prater --now
```

### 4. Monitor the service

```console
sudo journalctl -u nimbus-eth2-prater.service
```

This will show you the Nimbus logs at the default setting -- it should include regular "slot start" messages which will show your sync progress.

For more options, see [here](https://www.raspberrypi.org/documentation/linux/usage/systemd.md).


