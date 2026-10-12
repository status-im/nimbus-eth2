# beacon_chain
# Copyright (c) 2026 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at https://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at https://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.

# https://github.com/anthropics/oss-scanner/blob/main/templates/Dockerfile
# This file must set up the environment, install your project's dependencies and build the project.
# The scanner builds it with your repository as the build context, so `COPY . /src` puts the checkout inside
# the image. Network access is available during this Dockerfile build and is removed after this point, so
# all code that an agent might need to perform its tests must be fetched here.
# docker/dist/base_image/Dockerfile.amd64
FROM ubuntu:22.04
SHELL ["/bin/bash", "-c"]
ENV DEBIAN_FRONTEND=noninteractive TZ="Etc/UTC"
RUN apt-get -qq update \
 && apt-get -qq -y install build-essential git-lfs &>/dev/null \
 && apt-get -qq clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Build the project as its maintainers build it, with debug info (-g1) and frame pointers. A step that fails fails the
# build, and primary_contact gets the log.
# docker/dist/Dockerfile.amd64
RUN BUILD_TOOLS=1 NIMBUS_ETH2_DIR=/src docker/dist/entry_point.sh Linux_amd64

# Add a reference copy of implemented specs.
RUN SPEC_VERSION=$(sed -n 's/^const SPEC_VERSION\* = "\(.*\)"$/\1/p' /src/beacon_chain/spec/datatypes/base.nim) \
 && test -n "${SPEC_VERSION}" \
 && git clone --branch "v${SPEC_VERSION}" --config advice.detachedHead=false --depth 1 --quiet \
      https://github.com/ethereum/consensus-specs.git /specs/ethereum/consensus-specs
RUN for REPO in \
        ethereum/beacon-APIs \
        ethereum/builder-specs \
        ethereum/devp2p \
        ethereum/execution-apis \
        ethereum/keymanager-APIs \
        ethereum/remote-signing-api \
        libp2p/specs; do \
      git clone --depth 1 --quiet "https://github.com/${REPO}.git" "/specs/${REPO}" || exit 1; \
    done

# Run the cheap tests so you know the image works, but do not let a failing test abort the build. Leave anything worth
# exercising (binaries, test drivers, examples) where threat_model.md says it is.
RUN cd /src/build \
 && for BINARY in nimbus_beacon_node nimbus_validator_client nimbus_signing_node nimbus_light_client; do \
      ./${BINARY} --version || echo "WARNING: ${BINARY} reported failures"; \
    done
