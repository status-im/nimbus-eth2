# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# Nimbus PQ devnet image: the beacon node, which proves and verifies PQ
# signature aggregates in its own process.
#
# Build from the repository root, after `make nimbus_beacon_node`:
#
#   docker build -f docker/pq-devnet/Dockerfile -t nimbus-eth2/pq-devnet-1 .
#
# The beacon node is the host build (`build/nimbus_beacon_node`), so the
# runtime base matches an Ubuntu 24.04 host.

FROM ubuntu:24.04
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
  && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /home/user/nimbus-eth2/build
COPY build/nimbus_beacon_node \
  /home/user/nimbus-eth2/build/nimbus_beacon_node
RUN chmod 755 /home/user/nimbus-eth2/build/nimbus_beacon_node
WORKDIR /home/user/nimbus-eth2
ENTRYPOINT ["/home/user/nimbus-eth2/build/nimbus_beacon_node"]
