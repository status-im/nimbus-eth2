FROM debian:bullseye-slim AS build

SHELL ["/bin/bash", "-c"]

RUN apt-get -qq update \
 && apt-get -qq -y install build-essential make wget libpcre3-dev golang-go git &>/dev/null \
 && apt-get -qq clean

# let Docker cache this between Git revision and testnet version changes
RUN cd /root \
 && git clone https://github.com/status-im/nim-beacon-chain.git \
 && cd nim-beacon-chain \
 && { make &>/dev/null || true; } \
 && make -j$(nproc) update \
 && make deps

# Please note that the commands above have the goal of caching the compilation
# of Nim and p2pd, but don't depend on the current git revision. This means
# that the cache can become outdated over time and you'll start seeing Nim
# being compiled on every run. If this happens, just prune your docker cache
# to get a fresh up-to-date version of Nim and p2pd.
ARG GIT_REVISION
ARG NETWORK_NIM_FLAGS
ARG MARCH_NIM_FLAGS

RUN cd /root/nim-beacon-chain \
 && git fetch \
 && git reset --hard ${GIT_REVISION} \
 && make -j$(nproc) update \
 && make LOG_LEVEL=TRACE NIMFLAGS="-d:debug -d:insecure -d:testnet_servers_image ${NETWORK_NIM_FLAGS} ${MARCH_NIM_FLAGS}" beacon_node

# --------------------------------- #
# Starting new image to reduce size #
# --------------------------------- #
FROM debian:bullseye-slim

SHELL ["/bin/bash", "-c"]

RUN apt-get -qq update \
 && apt-get -qq -y install libpcre3 psmisc &>/dev/null \
 && apt-get -qq clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY run_in_docker.sh /usr/bin/run_beacon_node.sh
COPY --from=build /root/nim-beacon-chain/build/beacon_node /usr/bin/beacon_node
COPY --from=build /root/nim-beacon-chain/vendor/go/bin/p2pd /usr/bin/p2pd

MAINTAINER Zahary Karadjov <zahary@status.im>
LABEL description="Nimbus installation that can act as an ETH2 network bootstrap node."

# TODO: This custom entry script is necessary only because we must clean up
#       temporary files left by previous executions of the Go daeamon.
#       We should be able to remove it once we have a native LibP2P impl.
ENTRYPOINT ["/usr/bin/run_beacon_node.sh"]

