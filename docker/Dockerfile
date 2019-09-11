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
 && git clone https://github.com/status-im/nimbus.git \
 && cd nimbus \
 && git reset --hard ${GIT_REVISION} \
 && make update deps vendor/go/bin/p2pd nat-libs \
 && cp vendor/go/bin/p2pd /usr/bin/p2pd \
 && cp docker/beacon_node/run_in_docker.sh /usr/bin/run_beacon_node.sh

ARG NETWORK
ARG NETWORK_TYPE

RUN cd nimbus \
 && set -a \
 && . vendor/nim-beacon-chain/scripts/${NETWORK}.env \
 && ./env.sh nim \
      -o:/usr/bin/beacon_node \
      -d:release \
      --debugger:native \
      --debugInfo \
      -d:"network_type=${NETWORK_TYPE}" \
      -d:SHARD_COUNT=${SHARD_COUNT} \
      -d:SLOTS_PER_EPOCH=${SLOTS_PER_EPOCH} \
      -d:SECONDS_PER_SLOT=${SECONDS_PER_SLOT} \
      -d:chronicles_log_level=DEBUG \
      -d:chronicles_sinks=json \
      c vendor/nim-beacon-chain/beacon_chain/beacon_node.nim

# --------------------------------- #
# Starting new image to reduce size #
# --------------------------------- #
FROM debian:9-slim

RUN apt update \
 && apt install -y librocksdb-dev curl \
 && apt clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=build /usr/bin/beacon_node /usr/bin/beacon_node
COPY --from=build /usr/bin/run_beacon_node.sh /usr/bin/run_beacon_node.sh
COPY --from=build /usr/bin/p2pd /usr/bin/p2pd

MAINTAINER Zahary Karadjov <zahary@status.im>
LABEL description="Nimbus installation that can act as an ETH2 network bootstrap node."

ENTRYPOINT ["/usr/bin/run_beacon_node.sh"]
