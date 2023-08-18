# Docker images

Docker images for the [Nimbus beacon node](https://hub.docker.com/r/statusim/nimbus-eth2) and the [Nimbus validator client](https://hub.docker.com/r/statusim/nimbus-validator-client) are available at docker hub.

We have version-specific Docker tags (e.g. `statusim/nimbus-eth2:amd64-v1.2.3`) and a tag for the latest image (e.g. `statusim/nimbus-eth2:amd64-latest`).

These images contain the same binaries as the [release tarballs](./binaries.md) inside a `debian:bullseye-slim` image, running under a user imaginatively named `user`, with UID:GID of 1000:1000.

The binaries are placed under the `/home/user/` directory which is also the default *WORKDIR*.
The *ENTRYPOINT* of the image is configured to directly launch the respective binary without any extra arguments.

## Usage

Before running Nimbus via docker, you need to prepare a data directory and mount it in docker.

It is recommended that you mount the directory at `/home/user/data` and pass `--data-dir=data/beacon_node/mainnet_0` to all `nimbus_beacon_node` commands.

```sh
mkdir data
docker run -it --rm \
  -v ${PWD}/data:/home/user/data \
  statusim/nimbus-eth2:amd64-latest \
  --data-dir=data/beacon_node/mainnet_0
  --network=mainnet \
  [other options]
```

Similarly, to launch a Nimbus validator client you can use the following command:

```sh
mkdir data
docker run -it --rm \
  -v ${PWD}/data:/home/user/data \
  statusim/nimbus-validator_client:amd64-latest \
  --data-dir=data/validator_client/mainnet_0 \
  [other options]
```

!!! warning
    Do not use the same data directory for beacon node and validator client!
    They will both try to load the same keys which may result in slashing.

### Docker compose

Our preferred setup is using `docker-compose`.
You can use one of our [example configuration files](https://github.com/status-im/nimbus-eth2/tree/stable/docker/dist/binaries) as a base for your own custom configuration:

```sh
mkdir data
docker-compose -f docker-compose-example1.yml up --quiet-pull --no-color --detach
```

!!! note
    The rather voluminous logging is done on `stdout`, so you might want to change the system-wide Docker logging defaults (which dumps everything in `/var/lib/docker/containers/CONTAINER_ID/CONTAINER_ID-json.log`) to something like `syslog`.
    We recommend using a log rotation system with appropriate intervals for logs of this size.
