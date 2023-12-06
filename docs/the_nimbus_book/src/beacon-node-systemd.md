# Set up a systemd service

This page will take you through how to set up a `systemd` service for your beacon node.

`systemd` is used in order to have a command or a program run when your device boots (i.e. add it as a service).
Once this is done, you can start/stop enable/disable from the linux prompt.

!!! abstract "`systemd`"
    [`systemd`](https://systemd.io/) is a service manager designed specifically for Linux: it cannot be used on Windows / Mac.
    You can find out more about `systemd` [here](https://fedoramagazine.org/what-is-an-init-system/).

!!! note "Package manager installations"
    When installing Nimbus via your [package manager](./binaries.md), a user and service will already have been created for you and you can skip straight to the configuration section.

### 1. Create a dedicated user

We will start by creating a dedicated user and [data directory](./data-dir.md) for Nimbus.
The same user can also be used for the execution client.

```sh
# Create the `nimbus` group
sudo groupadd nimbus

# Create the `nimbus` user in the `nimbus` group - we will use /var/lib/nimbus as data directory.
sudo useradd -g nimbus nimbus -m -d /var/lib/nimbus
```

### 2. Create the service file

`systemd` services are created by placing a [service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) file in `/etc/systemd/system`, or, if Nimbus was installed by a package manager, `/usr/lib/systemd/system`.

A good starting point is the [example service file](https://raw.githubusercontent.com/status-im/nimbus-eth2/stable/scripts/package_src/nimbus_beacon_node/image/lib/systemd/system/nimbus_beacon_node.service) in the Nimbus repository.

```sh
# Download example service file and save it to `/etc/systemd/system/nimbus_beacon_node.service`
curl -s https://raw.githubusercontent.com/status-im/nimbus-eth2/stable/scripts/package_src/nimbus_beacon_node/image/lib/systemd/system/nimbus_beacon_node.service | sudo tee /etc/systemd/system/nimbus_beacon_node.service > /dev/null
```

The format of service files is documented in the [systemd manual](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).

!!! tip
    Automatic restarts increase the risk that the doppelganger detection fails - set `RestartPreventExitStatus=129` to prevent this from happening

### 3. Configure your service

Services are configured either by editing the service file directly or using `systemctl edit` to create an override.

```sh
# Edit the systemd file to match your installation
sudo vi /etc/systemd/system/nimbus_beacon_node.service

# If you installed nimbus via the package manager, use `systemctl edit` instead
sudo systemctl edit nimbus_beacon_node.service
```

The service file contains several options for controlling Nimbus.
Important options include:

* `Environment=NETWORK`: set this to `mainnet`, `holesky` or `sepolia`, depending on which network you want to connect to
* `Environment=WEB3_URL`: point this to your execution client, see the [Execution Client](./eth1.md) setup guide
* `Environment=REST_ENABLED`: REST is used to interact with the beacon node, in particular when setting up a separate Validator Client, see the [REST API](./rest-api.md) guide
* `Environment=METRICS_ENABLED`: metrics are used for monitoring the node, see the [metrics](./metrics-pretty-pictures.md) setup guide
* `ExecStart=`: custom options, see the [options](./options.md) guide

!!! note
    The example assumes Nimbus was installed in `/usr/bin/nimbus_beacon_node`.
    If you installed Nimbus elsewhere, make sure to update this path.

### 4. Notify systemd of the newly added service

Every time you add or update a service, the `systemd` daemon must be notified of the changes:

```sh
sudo systemctl daemon-reload
```

### 4. Start the service

```sh
# start the beacon node
sudo systemctl start nimbus_beacon_node

# (Optional) Set the beacon node to start automatically at boot
sudo systemctl enable nimbus_beacon_node
```

### 5. Check the status of the service

`systemctl status` will show if your beacon node is up and running, or has stopped for some reason.

```sh
sudo systemctl status nimbus_beacon_node.service
```

You can also follow the logs using the following command:

```sh
sudo journalctl -uf nimbus_beacon_node.service
```

This will show you the Nimbus logs at the default setting — it should include regular "slot start" messages which will show your [sync progress](./keep-an-eye.md#keep-track-of-your-syncing-progress).
Press `ctrl-c` to stop following the logs.

To rewind logs — by one day, say — run:

```sh
sudo journalctl -u nimbus_beacon_node.service --since yesterday
```

## Import validator keys

Before you start, familiarize yourself with the [standard way of importing validators](./run-a-validator.md#2-import-your-validator-keys).

Make sure you use the correct [data directory](./data-dir.md).
Look for the `--data-dir` option in the `.service` file.

When using a service, the beacon node is running as a different user.
Look for the `User=` option in the `.service`.
Here we assume that the user is called `nimbus`.

The key import must be performed as this user in order for the key files to have the correct permission:

```
# Run import command as the `nimbus` user
sudo -u nimbus /usr/bin/nimbus_beacon_node deposits import --data-dir=/var/lib/nimbus/shared_mainnet_0 /path/to/keys
```

!!! note
    Make sure to use the same `--data-dir` option as is used in the service file!
    Some guides use `--data-dir=/var/lib/nimbus` instead.

## Running multiple beacon nodes

You can run multiple beacon nodes on the same machine simply by copying the `.service` file and adjusting the parameters.

When running multiple beacon nodes, make sure that each service:

* has its own `.service` file
* has its own `--data-dir`
* has its own `--*-port` settings

## Further examples

- A [service template file](https://github.com/chfast/ethereum-node/blob/main/nimbus%40.service) by Pawel Bylica which allows you to start two services at the same time, e.g. `nimbus@holesky.service` and `nimbus@mainnet.service`.
- The [EthereumOnARM](https://github.com/EOA-Blockchain-Labs/ethereumonarm/blob/main/fpm-package-builder/l1-clients/consensus-layer/nimbus/extras/nimbus-beacon.service) project maintains a service file as part of their Ethereum installation package repository.
