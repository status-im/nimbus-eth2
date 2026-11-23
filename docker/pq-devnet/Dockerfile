# Nimbus PQ devnet image: the beacon node plus the leanVM sidecar that proves
# and verifies PQ signature aggregates.
#
# Build from the repository root, after `make nimbus_beacon_node`:
#
#   docker build -f docker/pq-devnet/Dockerfile -t nimbus-eth2/pq-devnet-0 .
#
# The sidecar is built here from the pinned leanVM commit. The beacon node is
# the host build (`build/nimbus_beacon_node`), so the runtime base matches an
# Ubuntu 24.04 host.

FROM rust:1-bookworm AS sidecar
ARG LEANVM_REV=241b009a61ba5fde797d1213b5bf76310f0d5060
# The fast kernels on x86_64; clear on other architectures
ARG SIDECAR_RUSTFLAGS="-C target-feature=+avx2,+pclmulqdq"
RUN git clone -q https://github.com/leanEthereum/leanVM /leanVM \
  && cd /leanVM \
  && git checkout -q "${LEANVM_REV}" \
  && RUSTFLAGS="${SIDECAR_RUSTFLAGS}" cargo build --release \
       -p leanvm-sidecar --features experimental_prover

FROM ubuntu:24.04
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libstdc++6 \
  && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /home/user/nimbus-eth2/build
COPY build/nimbus_beacon_node \
  /home/user/nimbus-eth2/build/nimbus_beacon_node.bin
COPY --from=sidecar /leanVM/target/release/leanvm-sidecar \
  /usr/local/bin/leanvm-sidecar
COPY docker/pq-devnet/nimbus-pq-bn.sh \
  /home/user/nimbus-eth2/build/nimbus_beacon_node
RUN chmod 755 /home/user/nimbus-eth2/build/nimbus_beacon_node \
  /home/user/nimbus-eth2/build/nimbus_beacon_node.bin \
  /usr/local/bin/leanvm-sidecar
WORKDIR /home/user/nimbus-eth2
ENTRYPOINT ["/home/user/nimbus-eth2/build/nimbus_beacon_node"]
