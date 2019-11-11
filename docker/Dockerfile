FROM statusteam/nim-base AS build

RUN apt-get -qq update \
 && apt-get -qq -y install build-essential make wget 2>/dev/null >/dev/null

RUN export GO_TAR_GZ=go1.12.6.linux-amd64.tar.gz \
 && cd /tmp/ \
 && wget --progress=dot:giga https://dl.google.com/go/$GO_TAR_GZ \
 && tar -xf $GO_TAR_GZ \
 && mv go /usr/local \
 && rm $GO_TAR_GZ

ARG GIT_REVISION

RUN export GOROOT=/usr/local/go \
 && export PATH=$GOROOT/bin:$PATH \
 && git clone https://github.com/status-im/nim-beacon-chain.git \
 && cd nim-beacon-chain \
 && git reset --hard ${GIT_REVISION} \
 && { make 2>/dev/null >/dev/null || true; } \
 && make -j8 update \
 && make deps \
 && cp vendor/go/bin/p2pd /usr/bin/p2pd \
 && cp docker/run_in_docker.sh /usr/bin/run_beacon_node.sh

ARG NETWORK
ARG NETWORK_TYPE

RUN cd nim-beacon-chain \
 && set -a \
 && . scripts/${NETWORK}.env \
 && ./env.sh nim \
      -o:/usr/bin/beacon_node \
      -d:release \
      -d:insecure \
      --debugger:native \
      --debugInfo \
      --verbosity:0 \
      --hints:off \
      --warnings:off \
      -d:"network_type=${NETWORK_TYPE}" \
      -d:"SHARD_COUNT=${SHARD_COUNT}" \
      -d:"SLOTS_PER_EPOCH=${SLOTS_PER_EPOCH}" \
      -d:"SECONDS_PER_SLOT=${SECONDS_PER_SLOT}" \
      -d:"chronicles_log_level=DEBUG" \
      -d:"testnet_servers_image" \
      c beacon_chain/beacon_node.nim

# --------------------------------- #
# Starting new image to reduce size #
# --------------------------------- #
FROM debian:9-slim

RUN apt-get -qq update \
 && apt-get -qq -y install librocksdb-dev psmisc 2>/dev/null >/dev/null \
 && apt-get -qq clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=build /usr/bin/beacon_node /usr/bin/beacon_node
COPY --from=build /usr/bin/run_beacon_node.sh /usr/bin/run_beacon_node.sh
COPY --from=build /usr/bin/p2pd /usr/bin/p2pd

MAINTAINER Zahary Karadjov <zahary@status.im>
LABEL description="Nimbus installation that can act as an ETH2 network bootstrap node."

ARG GIT_REVISION
RUN echo Built from Git revision: ${GIT_REVISION}

# TODO: This custom entry script is necessary only because we must clean up
#       temporary files left by previous executions of the Go daeamon.
#       We should be able to remove it once we have a native LibP2P impl.
ENTRYPOINT ["/usr/bin/run_beacon_node.sh"]

