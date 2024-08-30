# Copyright (c) 2024 Status Research & Development GmbH
# Licensed under either of
#  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
#    http://www.apache.org/licenses/LICENSE-2.0)
#  * MIT license ([LICENSE-MIT](LICENSE-MIT) or
#    http://opensource.org/licenses/MIT)
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

FROM debian:testing-slim AS build

SHELL ["/bin/bash", "-c"]

RUN apt-get clean && apt update \
 && apt -y install build-essential git-lfs

RUN ldd --version ldd

ADD . /root/nimbus-eth2

RUN cd /root/nimbus-eth2 \
 && make -j$(nproc) update \
 && make -j$(nproc) V=1 NIMFLAGS="-d:const_preset=mainnet -d:disableMarchNative" LOG_LEVEL=TRACE nimbus_beacon_node


# --------------------------------- #
# Starting new image to reduce size #
# --------------------------------- #
FROM debian:testing-slim as deploy

SHELL ["/bin/bash", "-c"]
RUN apt-get clean && apt update \
 && apt -y install build-essential
RUN apt update && apt -y upgrade

RUN ldd --version ldd

RUN rm -rf /home/user/nimbus-eth2/build/nimbus_beacon_node

# "COPY" creates new image layers, so we cram all we can into one command
COPY --from=build /root/nimbus-eth2/build/nimbus_beacon_node /home/user/nimbus-eth2/build/nimbus_beacon_node

ENV PATH="/home/user/nimbus-eth2/build:${PATH}"
ENTRYPOINT ["nimbus_beacon_node"]
WORKDIR /home/user/nimbus-eth2/build

STOPSIGNAL SIGINT