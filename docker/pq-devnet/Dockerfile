# Nimbus PQ devnet image: the beacon node plus the leanVM sidecar that proves
# and verifies PQ signature aggregates. Binaries are built on an Ubuntu 24.04
# host, so the runtime base matches it.
FROM ubuntu:24.04
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
  && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /home/user/nimbus-eth2/build
COPY nimbus_beacon_node /home/user/nimbus-eth2/build/nimbus_beacon_node.bin
COPY leanvm-sidecar /usr/local/bin/leanvm-sidecar
COPY nimbus-pq-bn.sh /home/user/nimbus-eth2/build/nimbus_beacon_node
RUN chmod +x /home/user/nimbus-eth2/build/nimbus_beacon_node \
  /home/user/nimbus-eth2/build/nimbus_beacon_node.bin \
  /usr/local/bin/leanvm-sidecar
WORKDIR /home/user/nimbus-eth2
ENTRYPOINT ["/home/user/nimbus-eth2/build/nimbus_beacon_node"]
