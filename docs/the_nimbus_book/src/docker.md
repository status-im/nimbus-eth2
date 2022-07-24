# Docker images

Docker images are available from [Docker Hub](https://hub.docker.com/r/statusim/nimbus-eth2)  .

We have version-specific Docker tags (`statusim/nimbus-eth2:amd64-v1.2.3`) and a tag for the latest image (`statusim/nimbus-eth2:amd64-latest`).

These images are simply the contents of [release tarballs](./binaries.md) inside a `debian:bullseye-slim` image, running under a user imaginatively named `user`, with UID:GID of 1000:1000.

The unpacked archive is in `/home/user/nimbus-eth2` which is also the default *WORKDIR*. The default *ENTRYPOINT* is the binary itself: `/home/user/nimbus-eth2/build/nimbus_beacon_node`

## Usage

Before running Nimbus via docker, you need to prepare a data directory and mount it in docker.

It is recommended that you mount the directory at `/home/user/nimbus-eth2/build/data` and pass `--data-dir=build/data/shared_mainnet_0` to all `nimbus_becaon_node` commands.

The wrapper script outlined below will set the data directory automatically.

```sh
mkdir data
docker run -it --rm \
  -v ${PWD}/data:/home/user/nimbus-eth2/build/data \
  statusim/nimbus-eth2:amd64-latest \
  --data-dir=build/data/shared_mainnet_0
  --network=mainnet [other options]
```

### Wrapper script

If you wish, you can choose to use a wrapper script instead:

```sh
mkdir data
docker run -it --rm \
  -v ${PWD}/data:/home/user/nimbus-eth2/build/data \
  --entrypoint /home/user/nimbus-eth2/run-mainnet-beacon-node.sh \
  statusim/nimbus-eth2:amd64-latest [other options]
```

### Docker compose

Our preferred setup is using `docker-compose`. You can use one of our [example configuration files](https://github.com/status-im/nimbus-eth2/tree/stable/docker/dist/binaries) as a base for your own custom configuration:

```sh
mkdir data
docker-compose -f docker-compose-example1.yml up --quiet-pull --no-color --detach
```

!!! note
    The rather voluminous logging is done on `stdout`, so you might want to change the system-wide Docker logging defaults (which dumps everything in `/var/lib/docker/containers/CONTAINER_ID/CONTAINER_ID-json.log`) to something like `syslog`. We recommend using a log rotation system with appropriate intervals for logs of this size.
