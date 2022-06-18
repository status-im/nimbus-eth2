# Set up a systemd service

This page will take you through how to set up a `systemd` service for your beacon node.

`systemd` is used in order to have a command or program run when your device boots (i.e. add it as a service). Once this is done, you can start/stop enable/disable from the linux prompt.

> [`systemd`](https://systemd.io/) is a service manager designed specifically for Linux - it cannot be used on Windows / Mac. You can get more information about systemd [here](https://fedoramagazine.org/what-is-an-init-system/)

When installing Nimbus via your package manager, a user and service will already have been created for you and you can skip straight to the configuration section.

### 1. Create a dedicated user

It is recommended that you create a dedicated user and group for running Nimbus. The same user can also be used for the execution client.

```console
# Create the `nimbus` group
sudo groupadd nimbus

# Create the `nimbus` user in the `nimbus` group - chain data will be stored in /var/lib/nimbus
sudo useradd -g nimbus nimbus -m -d /var/lib/nimbus
```

### 2. Create the service file

`systemd` services are created by placing a [service](https://www.freedesktop.org/software/systemd/man/systemd.service.html) file in `/etc/systemd/system`, or, if Nimbus was installed by a package manager, `/usr/lib/systemd/system`.

A good starting point is the [example service file](https://github.com/status-im/nimbus-eth2/blob/unstable/scripts/package_image/usr/lib/systemd/system/nimbus_beacon_node.service) in the Nimbus repository.

```console
# Download example service file and save it to `/etc/systemd/system/nimbus_beacon_node.service`
curl -s https://raw.githubusercontent.com/status-im/nimbus-eth2/stable/scripts/package_image/usr/lib/systemd/system/nimbus_beacon_node.service | sudo tee /etc/systemd/system/nimbus_beacon_node.service > /dev/null
```

The format of service files is documented in the [systemd manual](https://www.freedesktop.org/software/systemd/man/systemd.service.html).

> 🛈 Automatic restarts increase the risk that the doppelganger detection fails - set `RestartPreventExitStatus=1031` to prevent this from happening

### 3. Configure your service

Services are configured either by editing the service file directly or using `systemctl edit` to create an override.

```console
# Edit the systemd file to match your installation
sudo vi /etc/systemd/system/nimbus_beacon_node.service

# If you installed nimbus via the package manager, use `systemctl edit` instead
sudo systemctl edit nimbus_beacon_node.service
```

The service file contains several options for controlling Nimbus. Important options include:

* `Environment=NETWORK`: set this to `mainnet`, `prater` or `ropsten`, depending on which network you want to connect to
* `Environment=WEB3_URL`: point this to your execution client - see the [Execution Client](./eth1.md) setup guide
* `Environment=REST_ENABLED`: REST is used to interact with the beacon node, in particular when setting up a separate Validator Client - see the [REST API](./rest-api.md) guide
* `Environment=METRICS_ENABLED`: Metrics are used for monitoring the node - see the [metrics](./metrics-pretty-pictures.md) setup guide
* `ExecStart=`: Custom options - see the [options](./options.md) guide

The example assumes Nimbus was installed in `/usr/bin/nimbus_beacon_node` - if you installed Nimbus elsewhere, make sure to update this path.

### 4. Notify systemd of the newly added service

Every time you add or update a service, the `systemd` daemon must be notified of the changes:

```console
sudo systemctl daemon-reload
```

### 4. Start the service

```console
# start the beacon node
sudo systemctl start nimbus_beacon_node

# (Optional) Set the beacon node to start automatically at boot
sudo systemctl enable nimbus_beacon_node
```

### 5. Check the status of the service

`systemctl status` will show if your beacon node is up and running, or has stopped for some reason.

```console
sudo systemctl status nimbus_beacon_node.service
```

You can also inspect the logs using the following command:

```console
sudo journalctl -u nimbus_beacon_node.service
```

This will show you the Nimbus logs at the default setting -- it should include regular "slot start" messages which will show your [sync progress](./keep-an-eye.md#keep-track-of-your-syncing-progress).

To rewind logs - by one day, say - run:

```console
sudo journalctl -u nimbus_beacon_node.service --since yesterday
```

## Running multiple beacon nodes

You can run multiple beacon nodes on the same machine simply by copying the `.service` file and adjusting the parameters.

When running multiple beacon nodes, make sure that each service:

* has its own `.service` file
* has its own `--data-dir`
* has its own `--*-port` settings

## Further examples

- A [service template file](https://github.com/chfast/ethereum-node/blob/main/nimbus%40.service) by Pawel Bylica which allows you to start two services at the same time: e.g. `nimbus@prater.service` and `nimbus@mainnet.service`.
- The [EthereumOnARM](https://github.com/diglos/ethereumonarm/blob/main/fpm-package-builder/nimbus/extras/nimbus.service) project maintains a service file as part of their Ethereum installation package repository.
