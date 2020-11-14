FROM debian:bullseye-slim

SHELL ["/bin/bash", "-c"]

RUN apt-get -qq update \
 && apt-get -qq -y install build-essential git &>/dev/null \
 && apt-get -qq clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

STOPSIGNAL SIGINT

COPY "entry_point.sh" "/root/"
ENTRYPOINT ["/root/entry_point.sh"]

