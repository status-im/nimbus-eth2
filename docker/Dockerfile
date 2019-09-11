FROM statusteam/nim-base AS build

RUN apt update \
 && apt install -y build-essential make wget \
 && apt clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN export GO_TAR_GZ=go1.12.6.linux-amd64.tar.gz \
 && cd /tmp/ \
 && wget https://dl.google.com/go/$GO_TAR_GZ \
 && tar -xvf $GO_TAR_GZ \
 && mv go /usr/local \
 && rm $GO_TAR_GZ

ARG GIT_REVISION

RUN export GOROOT=/usr/local/go \
 && export PATH=$GOROOT/bin:$PATH \
 && git clone https://github.com/status-im/nim-beacon-chain.git \
 && cd nim-beacon-chain \
 && git reset --hard ${GIT_REVISION} \
 && git submodule update --init --recursive

RUN cd nim-beacon-chain \
 && make build-system-checks

# TODO: The command above exits with 1, so we cannot chain it cleanly
RUN cd nim-beacon-chain \
 && export PATH=/usr/local/go/bin:$PATH \
 && make update deps \
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
      --debugger:native \
      --debugInfo \
      -d:"network_type=${NETWORK_TYPE}" \
      -d:"SHARD_COUNT=${SHARD_COUNT}" \
      -d:"SLOTS_PER_EPOCH=${SLOTS_PER_EPOCH}" \
      -d:"SECONDS_PER_SLOT=${SECONDS_PER_SLOT}" \
      -d:"chronicles_log_level=DEBUG" \
      -d:"chronicles_sinks=json" \
      c beacon_chain/beacon_node.nim

# --------------------------------- #
# Starting new image to reduce size #
# --------------------------------- #
FROM debian:9-slim

RUN apt update \
 && apt install -y librocksdb-dev curl psmisc \
 && apt clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=build /usr/bin/beacon_node /usr/bin/beacon_node
COPY --from=build /usr/bin/run_beacon_node.sh /usr/bin/run_beacon_node.sh
COPY --from=build /usr/bin/p2pd /usr/bin/p2pd

MAINTAINER Zahary Karadjov <zahary@status.im>
LABEL description="Nimbus installation that can act as an ETH2 network bootstrap node."

RUN echo Built from Git revision: ${GIT_REVISION}

# TODO: This custom entry script is necessary only because we must clean up
#       temporary files left by previous executions of the Go daeamon.
#       We should be able to remove it once we have a native LibP2P impl.
ENTRYPOINT ["/usr/bin/run_beacon_node.sh"]
