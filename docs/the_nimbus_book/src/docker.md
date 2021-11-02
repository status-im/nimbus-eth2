# Docker images

Docker images for end-users are generated and published automatically to [Docker Hub](https://hub.docker.com/r/statusim/nimbus-eth2) from the Nimbus-eth2 CI, by a GitHub action, whenever a new release is tagged in Git.

We have version-specific Docker tags (`statusim/nimbus-eth2:amd64-v1.2.3`) and a tag for the latest image (`statusim/nimbus-eth2:amd64-latest`).

These images are simply the contents of [release tarballs](./binaries.md) inside a `debian:bullseye-slim` image, running under a user imaginatively named `user`, with UID:GID of 1000:1000.

The unpacked archive is in `/home/user/nimbus-eth2` which is also the default *WORKDIR*. The default *ENTRYPOINT* is the binary itself: `/home/user/nimbus-eth2/build/nimbus\_beacon\_node`

## Usage

You need to create an external data directory and mount it as a volume inside the container, with  mounting point: `/home/user/nimbus-eth2/build/data`

```text
mkdir data
docker run -it --rm -v ${PWD}/data:/home/user/nimbus-eth2/build/data statusim/nimbus-eth2:amd64-latest [nimbus_beacon_node args here]
```


### Wrapper script
If you wish, you can choose to use a wrapper script instead:

```text
mkdir data
docker run -it --rm -v ${PWD}/data:/home/user/nimbus-eth2/build/data -e WEB3_URL="wss://mainnet.infura.io/ws/v3/YOUR_TOKEN" --entrypoint /home/user/nimbus-eth2/run-mainnet-beacon-node.sh statusim/nimbus-eth2:amd64-latest [nimbus_beacon_node args here]
```

### Docker compose
Our preferred setup is using `docker-compose`. You can use one of our [example configuration files](https://github.com/status-im/nimbus-eth2/tree/stable/docker/dist/binaries) as a base for your own custom configuration:

```text
mkdir data
docker-compose -f docker-compose-example1.yml up --quiet-pull --no-color --detach
```

> **Note:** The rather voluminous logging is done on `stdout`, so you might want to change the system-wide Docker logging defaults (which dumps everything in `/var/lib/docker/containers/CONTAINER_ID/CONTAINER_ID-json.log`) to something like `syslog`. We recommend using a log rotation system with appropriate intervals for logs of this size.

