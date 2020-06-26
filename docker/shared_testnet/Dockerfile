FROM debian:bullseye-slim

SHELL ["/bin/bash", "-c"]

RUN apt-get -qq update \
 && apt-get -qq -y install build-essential libpcre3-dev git &>/dev/null \
 && apt-get -qq clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ARG NETWORK
ENV NETWORK=${NETWORK}

STOPSIGNAL SIGINT
ENTRYPOINT ["/root/nim-beacon-chain/docker/shared_testnet/entry_point.sh"]

