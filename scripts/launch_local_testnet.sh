#!/usr/bin/env bash

# Copyright (c) 2020-2023 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

# Mostly a duplication of "tests/simulation/{start.sh,run_node.sh}", but with a focus on
# replicating testnets as closely as possible, which means following the Docker execution labyrinth.

set -euo pipefail

SCRIPTS_DIR="$(dirname "${BASH_SOURCE[0]}")"
cd "$SCRIPTS_DIR/.."
BUILD_DIR="$(pwd)/build"

VERBOSE="0"

log() {
  if [[ "${VERBOSE}" -ge "1" ]]; then
    echo "${@}"
  fi
}

source "$SCRIPTS_DIR/detect_platform.sh"

# Created processed that will be cleaned up when the script exits
PIDS_TO_WAIT=""

####################
# argument parsing #
####################

GETOPT_BINARY="getopt"
if [[ "${OS}" == "macos" ]]; then
  # Without the head -n1 constraint, it gets confused by multiple matches
  GETOPT_BINARY=$(find /opt/homebrew/opt/gnu-getopt/bin/getopt /usr/local/opt/gnu-getopt/bin/getopt 2> /dev/null | head -n1 || true)
  [[ -f "$GETOPT_BINARY" ]] || { echo "GNU getopt not installed. Please run 'brew install gnu-getopt'. Aborting."; exit 1; }
fi

! ${GETOPT_BINARY} --test > /dev/null
if [[ ${PIPESTATUS[0]} != 4 ]]; then
  # shellcheck disable=2016
  echo '`getopt --test` failed in this environment.'
  exit 1
fi

CURL_BINARY="$(command -v curl)" || { echo "Curl not installed. Aborting."; exit 1; }
JQ_BINARY="$(command -v jq)" || { echo "jq not installed. Aborting."; exit 1; }

OPTS="ht:n:d:g"
LONGOPTS="help,preset:,nodes:,data-dir:,remote-validators-count:,threshold:,signer-nodes:,signer-type:,with-ganache,stop-at-epoch:,disable-htop,use-vc:,disable-vc,enable-payload-builder,enable-logtrace,log-level:,base-port:,base-rest-port:,base-metrics-port:,base-vc-metrics-port:,base-vc-keymanager-port:,base-remote-signer-port:,base-remote-signer-metrics-port:,base-el-net-port:,base-el-rpc-port:,base-el-ws-port:,base-el-auth-rpc-port:,el-port-offset:,reuse-existing-data-dir,reuse-binaries,timeout:,kill-old-processes,eth2-docker-image:,lighthouse-vc-nodes:,run-geth,dl-geth,dl-nimbus-eth1,dl-nimbus-eth2,light-clients:,run-nimbus-eth1,verbose,altair-fork-epoch:,bellatrix-fork-epoch:,capella-fork-epoch:,deneb-fork-epoch:"

# default values
BINARIES=""
NUM_NODES="10"
DATA_DIR="local_testnet_data"
USE_HTOP="1"
: ${USE_VC:="1"}
USE_PAYLOAD_BUILDER="false"
: ${PAYLOAD_BUILDER_HOST:=127.0.0.1}
: ${PAYLOAD_BUILDER_PORT:=4888}
LIGHTHOUSE_VC_NODES="0"
LOG_LEVEL="DEBUG; TRACE:networking"
BASE_PORT="9000"
BASE_REMOTE_SIGNER_PORT="6000"
BASE_REMOTE_SIGNER_METRICS_PORT="6100"
BASE_METRICS_PORT="8008"
BASE_REST_PORT="7500"
BASE_VC_KEYMANAGER_PORT="8500"
BASE_VC_METRICS_PORT="9008"
BASE_EL_NET_PORT="30303"
BASE_EL_RPC_PORT="8545"
BASE_EL_WS_PORT="8546"
BASE_EL_AUTH_RPC_PORT="8551"
EL_PORT_OFFSET="10"
: ${REUSE_EXISTING_DATA_DIR:=0}
: ${REUSE_BINARIES:=0}
: ${NIMFLAGS:=""}
: ${MIN_DEPOSIT_SENDING_DELAY:=1}
: ${MAX_DEPOSIT_SENDING_DELAY:=25}
ENABLE_LOGTRACE="0"
STOP_AT_EPOCH=9999999
STOP_AT_EPOCH_FLAG=""
TIMEOUT_DURATION="0"
CONST_PRESET="mainnet"
KILL_OLD_PROCESSES="0"
ETH2_DOCKER_IMAGE=""
REMOTE_SIGNER_THRESHOLD=1
REMOTE_VALIDATORS_COUNT=0
LC_NODES=1
ACCOUNT_PASSWORD="nimbus"
RUN_GETH="0"
DL_GETH="0"
: ${DL_NIMBUS_ETH1:="0"}
: ${DL_NIMBUS_ETH2:="0"}

# TODO: Add command-line flags for these
: ${NIMBUS_ETH2_VERSION:=23.3.2}
: ${NIMBUS_ETH2_REVISION:=6c0d756d}

: ${BEACON_NODE_COMMAND:="./build/nimbus_beacon_node$EXE_EXTENSION"}
: ${CAPELLA_FORK_EPOCH:=0}
: ${DENEB_FORK_EPOCH:=50}
#NIMBUS EL VARS
RUN_NIMBUS_ETH1="0"
: ${NIMBUS_ETH1_BINARY:="./build/downloads/nimbus$EXE_EXTENSION"}
: ${WEB3SIGNER_VERSION:=23.1.0}
: ${WEB3SIGNER_DIR:="${BUILD_DIR}/downloads/web3signer-${WEB3SIGNER_VERSION}"}
: ${WEB3SIGNER_BINARY:="${WEB3SIGNER_DIR}/bin/web3signer$BAT_EXTENSION"}
: ${SIGNER_NODES:=0}
: ${SIGNER_TYPE:="nimbus"}
PORTS_TO_KILL=()
WEB3_ARG=()
CLEANUP_DIRS=()

print_help() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] -- [BEACON NODE OPTIONS]
E.g.: $(basename "$0") --nodes ${NUM_NODES} --stop-at-epoch 5 --data-dir "${DATA_DIR}" # defaults
CI run: $(basename "$0") --disable-htop -- --verify-finalization

  -h, --help                  show this help message
  -n, --nodes                 number of nodes to launch (default: ${NUM_NODES})
  -g, --with-ganache          simulate a genesis event based on a deposit contract
  -s, --stop-at-epoch         stop simulation at epoch (default: infinite)
  -d, --data-dir              directory where all the node data and logs will end up
                              (default: "${DATA_DIR}")
  --preset                    Const preset to be (default: mainnet)
  --base-port                 bootstrap node's Eth2 traffic port (default: ${BASE_PORT})
  --base-rest-port            bootstrap node's REST port (default: ${BASE_REST_PORT})
  --base-metrics-port         bootstrap node's metrics port (default: ${BASE_METRICS_PORT})
  --base-vc-keymanager-port   The first validator client keymanager port (default: ${BASE_VC_KEYMANAGER_PORT})
  --base-vc-metrics-port      The first validator client metrics port (default: ${BASE_VC_METRICS_PORT})
  --base-remote-signer-port   first remote signer's port (default: ${BASE_REMOTE_SIGNER_PORT})
  --base-remote-signer-metrics-port first remote signer's metrics port (default: ${BASE_REMOTE_SIGNER_METRICS_PORT})
  --base-el-net-port          first EL's network traffic port (default: ${BASE_EL_NET_PORT})
  --base-el-rpc-port          first EL's HTTP JSON-RPC port (default: ${BASE_EL_RPC_PORT})
  --base-el-ws-port           first EL's WebSocket web3 port (default: ${BASE_EL_WS_PORT})
  --base-el-auth-rpc-port     first EL's authenticated engine API port (default: ${BASE_EL_AUTH_RPC_PORT})
  --el-port-offset            offset to apply between ports of multiple ELs (default: ${EL_PORT_OFFSET})
  --disable-htop              don't use "htop" to see the nimbus_beacon_node processes
  --disable-vc                don't use validator client binaries for validators
                              (by default validators are split 50/50 between beacon nodes
                              and validator clients, with all beacon nodes being paired up
                              with a corresponding validator client)
  --lighthouse-vc-nodes       number of Lighthouse VC nodes (assigned before Nimbus VC nodes, default: ${LIGHTHOUSE_VC_NODES})
  --enable-logtrace           display logtrace analysis
  --log-level                 set the log level (default: "${LOG_LEVEL}")
  --reuse-existing-data-dir   instead of deleting and recreating the data dir, keep it and reuse everything we can from it
  --reuse-binaries            don't (re)build the binaries we need and don't delete them at the end (speeds up testing)
  --timeout                   timeout in seconds (default: ${TIMEOUT_DURATION} - no timeout)
  --kill-old-processes        if any process is found listening on a port we use, kill it (default: disabled)
  --eth2-docker-image         use docker image instead of compiling the beacon node
  --remote-validators-count   number of remote validators which will be generated
  --threshold                 used by a threshold secret sharing mechanism and determine how many shares are need to
                              restore signature of the original secret key
  --signer-nodes              number of remote signer nodes
  --signer-type               a script in the scripts/signers directory, used to launch remote signers
  --light-clients             number of light clients
  --run-nimbus-eth1           Run nimbush-eth1 as EL
  --run-geth                  Run geth EL clients
  --dl-geth                   Download geth binary if not found
  --dl-nimbus-eth2            Download Nimbus CL binary
  --verbose                   Verbose output
EOF
}

! PARSED=$(${GETOPT_BINARY} --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
if [[ ${PIPESTATUS[0]} != 0 ]]; then
  # getopt has complained about wrong arguments to stdout
  exit 1
fi

# read getopt's output this way to handle the quoting right
eval set -- "$PARSED"
while true; do
  case "$1" in
    -h|--help)
      print_help
      exit
      ;;
    -n|--nodes)
      NUM_NODES="$2"
      shift 2
      ;;
    --signer-nodes)
      SIGNER_NODES=$2
      shift 2
      ;;
    --signer-type)
      SIGNER_TYPE=$2
      shift 2
      ;;
    --remote-validators-count)
      REMOTE_VALIDATORS_COUNT=$2
      shift 2
      ;;
    --threshold)
      REMOTE_SIGNER_THRESHOLD=$2
      shift 2
      ;;
    -d|--data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    --preset)
      CONST_PRESET="$2"
      shift 2
      ;;
    --capella-fork-epoch)
      CAPELLA_FORK_EPOCH="$2"
      shift 2
      ;;
    --deneb-fork-epoch)
      DENEB_FORK_EPOCH="$2"
      shift 2
      ;;
    --stop-at-epoch)
      STOP_AT_EPOCH=$2
      STOP_AT_EPOCH_FLAG="--debug-stop-at-epoch=$2"
      shift 2
      ;;
    --disable-htop)
      USE_HTOP="0"
      shift
      ;;
    --disable-vc)
      USE_VC="0"
      shift
      ;;
    --use-vc)
      USE_VC="$2"
      shift 2
      ;;
    --enable-payload-builder)
      USE_PAYLOAD_BUILDER="true"
      shift
      ;;
    --enable-logtrace)
      ENABLE_LOGTRACE="1"
      shift
      ;;
    --log-level)
      LOG_LEVEL="$2"
      shift 2
      ;;
    --base-port)
      BASE_PORT="$2"
      shift 2
      ;;
    --base-rest-port)
      BASE_REST_PORT="$2"
      shift 2
      ;;
    --base-metrics-port)
      BASE_METRICS_PORT="$2"
      shift 2
      ;;
    --base-vc-keymanager-port)
      BASE_VC_KEYMANAGER_PORT="$2"
      shift 2
      ;;
    --base-vc-metrics-port)
      BASE_VC_METRICS_PORT="$2"
      shift 2
      ;;
    --base-remote-signer-port)
      BASE_REMOTE_SIGNER_PORT="$2"
      shift 2
      ;;
    --base-remote-signer-metrics-port)
      BASE_REMOTE_SIGNER_METRICS_PORT="$2"
      shift 2
      ;;
    --base-el-net-port)
      BASE_EL_NET_PORT="$2"
      shift 2
      ;;
    --base-el-rpc-port)
      BASE_EL_RPC_PORT="$2"
      shift 2
      ;;
    --base-el-ws-port)
      BASE_EL_WS_PORT="$2"
      shift 2
      ;;
    --base-el-auth-rpc-port)
      BASE_EL_AUTH_RPC_PORT="$2"
      shift 2
      ;;
    --el-port-offset)
      EL_PORT_OFFSET="$2"
      shift 2
      ;;
    --reuse-existing-data-dir)
      REUSE_EXISTING_DATA_DIR="1"
      shift
      ;;
    --reuse-binaries)
      REUSE_BINARIES="1"
      shift
      ;;
    --timeout)
      TIMEOUT_DURATION="$2"
      shift 2
      ;;
    --kill-old-processes)
      KILL_OLD_PROCESSES="1"
      shift
      ;;
    --eth2-docker-image)
      ETH2_DOCKER_IMAGE="$2"
      shift 2
      # TODO The validator client and light client are not being shipped with
      #      our docker images, so we must disable them:
      echo "warning: --eth-docker-image implies --disable-vc --light-clients=0"
      USE_VC="0"
      LC_NODES="0"
      ;;
    --lighthouse-vc-nodes)
      LIGHTHOUSE_VC_NODES="$2"
      shift 2
      ;;
    --light-clients)
      LC_NODES="$2"
      shift 2
      ;;
    --run-geth)
      RUN_GETH="1"
      shift
      ;;
    --dl-geth)
      DL_GETH="1"
      shift
      ;;
    --dl-nimbus-eth2)
      DL_NIMBUS_ETH2="1"
      shift
      ;;
    --run-nimbus-eth1)
      RUN_NIMBUS_ETH1="1"
      shift
      ;;
    --dl-nimbus-eth1)
      DL_NIMBUS_ETH1="1"
      shift
      ;;
    --verbose)
      VERBOSE="1"
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "argument parsing error"
      print_help
      exit 1
  esac
done
if [[ -n "${ETH2_DOCKER_IMAGE}" ]]; then
  if (( USE_VC || LC_NODES )); then
    echo "invalid config: USE_VC=${USE_VC} LC_NODES=${LC_NODES}"
    false
  fi
fi

# when sourcing env.sh, it will try to execute $@, so empty it
EXTRA_ARGS="$@"
if [[ $# != 0 ]]; then
  shift $#
fi

if [[ "$REUSE_EXISTING_DATA_DIR" == "0" ]]; then
  log "Deleting ${DATA_DIR}"
  rm -rf "${DATA_DIR}"
fi

rm -rf "${DATA_DIR}/pids/*"
mkdir -p "${DATA_DIR}/pids" "${DATA_DIR}/logs"

if [[ "${LIGHTHOUSE_VC_NODES}" != "0" && "${CONST_PRESET}" != "mainnet" ]]; then
  echo "The prebuilt Lighthouse binary we're using only supports mainnet. Aborting."
  exit 1
fi

scripts/makedir.sh "${DATA_DIR}"
echo x > "${DATA_DIR}/keymanager-token"

JWT_FILE="${DATA_DIR}/jwtsecret"
echo "Generating JWT file '$JWT_FILE'..."
openssl rand -hex 32 | tr -d "\n" > "${JWT_FILE}"

if [[ "$CONST_PRESET" == "minimal" ]]; then
  SECONDS_PER_SLOT=6
  SLOTS_PER_EPOCH=8
else
  SECONDS_PER_SLOT=12
  SLOTS_PER_EPOCH=32
fi

VALIDATORS_DIR="${DATA_DIR}/validators"
scripts/makedir.sh "${VALIDATORS_DIR}"

SECRETS_DIR="${DATA_DIR}/secrets"
scripts/makedir.sh "${SECRETS_DIR}"

USER_VALIDATORS=8
TOTAL_VALIDATORS=1024

# "Make" binary
if [[ "${OS}" == "windows" ]]; then
  MAKE="mingw32-make"
else
  MAKE="make"
fi

# number of CPU cores
if uname | grep -qi darwin; then
  NPROC="$(sysctl -n hw.logicalcpu)"
else
  NPROC="$(nproc)"
fi

# Kill all processes which have open ports in the array passed as parameter
kill_by_port() {
  local ports=("$@")
  for PORT in "${ports[@]}"; do
    for PID in $(lsof -n -i tcp:${PORT} -sTCP:LISTEN -t); do
      echo -n "Found old process listening on port ${PORT}, with PID ${PID}. "
      if [[ "${KILL_OLD_PROCESSES}" == "1" ]]; then
        echo "Killing it."
        kill -SIGKILL "${PID}" || true
      else
        echo "Aborting."
        exit 1
      fi
    done
  done
}

GETH_NUM_NODES="$(( NUM_NODES + LC_NODES ))"
NIMBUS_ETH1_NUM_NODES="$(( NUM_NODES + LC_NODES ))"
LAST_SIGNER_NODE_IDX=$(( SIGNER_NODES - 1 ))

if [[ "${RUN_GETH}" == "1" ]]; then
  source "${SCRIPTS_DIR}/geth_binaries.sh"

  if [[ $DENEB_FORK_EPOCH -lt $STOP_AT_EPOCH ]]; then
    download_geth_deneb
    GETH_BINARY="$GETH_DENEB_BINARY"
  else
    download_geth_capella
    GETH_BINARY="$GETH_CAPELLA_BINARY"
  fi

  source ./scripts/geth_vars.sh
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  . ./scripts/nimbus_el_vars.sh
fi

# kill lingering processes from a previous run
if [[ "${OS}" != "windows" ]]; then
  which lsof &>/dev/null || \
    { echo "'lsof' not installed and we need it to check for ports already in use. Aborting."; exit 1; }

  # Stop geth nodes
  if [[ "${RUN_GETH}" == "1" ]]; then
    for GETH_NODE_IDX in $(seq 0 $GETH_LAST_NODE_IDX); do
      for PORT in ${GETH_NET_PORTS[GETH_NODE_IDX]} \
                  ${GETH_RPC_PORTS[GETH_NODE_IDX]} \
                  ${GETH_AUTH_RPC_PORTS[GETH_NODE_IDX]};
      do
        PORTS_TO_KILL+=("${PORT}")
      done
    done
  fi

  # Stop Nimbus EL nodes
  if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
    for NIMBUS_ETH1_NODE_IDX in $(seq 0 $NIMBUS_ETH1_LAST_NODE_IDX); do
      for PORT in ${NIMBUS_ETH1_NET_PORTS[NIMBUS_ETH1_NODE_IDX]} \
                  ${NIMBUS_ETH1_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]} \
                  ${NIMBUS_ETH1_AUTH_RPC_PORTS[NIMBUS_ETH1_NODE_IDX]};
      do
        PORTS_TO_KILL+=("${PORT}")
      done
    done
  fi

  # Stop Remote Signers
  for NUM_REMOTE in $(seq 0 $LAST_SIGNER_NODE_IDX); do
    for PORT in $(( BASE_REMOTE_SIGNER_PORT + NUM_REMOTE )) \
                $(( BASE_REMOTE_SIGNER_METRICS_PORT + NUM_REMOTE )) ; do
      PORTS_TO_KILL+=("${PORT}")
    done
  done

  # Stop Nimbus validator clients
  if [[ "${USE_VC}" == "1" ]]; then
    for NUM_NODE in $(seq 1 $NUM_NODES); do
      for PORT in $(( BASE_VC_METRICS_PORT + NUM_NODE - 1 )) \
                  $(( BASE_VC_KEYMANAGER_PORT + NUM_NODE - 1 )); do
        PORTS_TO_KILL+=("${PORT}")
      done
    done
  fi

  # Stop Nimbus CL nodes
  for NUM_NODE in $(seq 1 $NUM_NODES); do
    for PORT in $(( BASE_PORT + NUM_NODE - 1 )) $(( BASE_METRICS_PORT + NUM_NODE - 1)) $(( BASE_REST_PORT + NUM_NODE - 1)); do
      PORTS_TO_KILL+=("${PORT}")
    done
  done

  kill_by_port "${PORTS_TO_KILL[@]}"
fi

download_web3signer() {
  if [[ ! -d "${WEB3SIGNER_DIR}" ]]; then
    log "Downloading Web3Signer binary"

    WEB3SIGNER_TARBALL="web3signer-${WEB3SIGNER_VERSION}.tar.gz"
    WEB3SIGNER_URL="https://artifacts.consensys.net/public/web3signer/raw/names/web3signer.tar.gz/versions/${WEB3SIGNER_VERSION}/${WEB3SIGNER_TARBALL}"

    mkdir -p "${WEB3SIGNER_DIR}"
    "${CURL_BINARY}" -sSL "${WEB3SIGNER_URL}" \
      | tar -xzf - --directory "${WEB3SIGNER_DIR}" --strip-components=1
  fi
}

download_nimbus_eth1() {
  if [[ ! -e "${NIMBUS_ETH1_BINARY}" ]]; then
    case "${OS}-${ARCH}" in
      linux-amd64|linux-x86_64)
        NIMBUS_ETH1_PLATFORM=Linux_amd64
        ;;
      linux-arm|linux-arm32|linux-aarch32)
        NIMBUS_PLATFORM=Linux_arm32v7
        ;;
      linux-arm64|linux-aarch64)
        NIMBUS_ETH1_PLATFORM=Linux_arm64v8
        ;;
      macos-amd64|macos-x86_64)
        NIMBUS_ETH1_PLATFORM=macOS_arm64
        ;;
      macos-arm64|macos-aarch64)
        NIMBUS_ETH1_PLATFORM=macOS_amd64
        ;;
      windows-amd64|windows-x86_64)
        NIMBUS_ETH1_PLATFORM=Windows_amd64
        ;;
      *)
        echo "No nimbus-eth1 binaries available for ${OS}-${ARCH}"
        exit 1
        ;;
    esac

    NIMBUS_ETH1_FULL_BINARY_VERSION=20221205_f4cacdfc
    NIMBUS_ETH1_TARBALL_NAME="nimbus-eth1_${NIMBUS_ETH1_PLATFORM}_${NIMBUS_ETH1_FULL_BINARY_VERSION}.tar.gz"

    NIMBUS_ETH1_TARBALL_URL="https://github.com/status-im/nimbus-simulation-binaries/raw/master/nimbus-eth1/nightly-20221205/${NIMBUS_ETH1_TARBALL_NAME}"

    log "Downloading Nimbus ETH1 binary"

    "${CURL_BINARY}" -o "$NIMBUS_ETH1_TARBALL_NAME" -sSLO "$NIMBUS_ETH1_TARBALL_URL"
    local tmp_extract_dir
    tmp_extract_dir=$(mktemp -d nimbus-eth1-tarball-XXX)
    CLEANUP_DIRS+=("$tmp_extract_dir")
    tar -xzf "${NIMBUS_ETH1_TARBALL_NAME}" -C "$tmp_extract_dir" --strip-components=1
    mkdir -p "$(dirname "$NIMBUS_ETH1_BINARY")"
    mv "$tmp_extract_dir/build/nimbus$EXE_EXTENSION" "$NIMBUS_ETH1_BINARY"
    chmod +x "$NIMBUS_ETH1_BINARY"
    patchelf_when_on_nixos "$NIMBUS_ETH1_BINARY"
  fi
}

download_nimbus_eth2() {
  if [[ ! -e "${BEACON_NODE_COMMAND}" ]]; then
    case "${OS}-${ARCH}" in
      linux-amd64|linux-x86_64)
        NIMBUS_PLATFORM=Linux_amd64
        ;;
      linux-arm|linux-arm32|linux-aarch32)
        NIMBUS_PLATFORM=Linux_arm32v7
        ;;
      linux-arm64|linux-aarch64)
        NIMBUS_PLATFORM=Linux_arm64v8
        ;;
      macos-amd64|macos-x86_64)
        NIMBUS_PLATFORM=macOS_amd64
        ;;
      macos-arm64|macos-aarch64)
        NIMBUS_PLATFORM=macOS_arm64
        ;;
      windows-amd64|windows-x86_64)
        NIMBUS_PLATFORM=Windows_amd64
        ;;
    esac

    NIMBUS_ETH2_FULL_BINARY_VERSION="${NIMBUS_ETH2_VERSION}_${NIMBUS_ETH2_REVISION}"
    NIMBUS_ETH2_TARBALL_NAME="nimbus-eth2_${NIMBUS_PLATFORM}_${NIMBUS_ETH2_FULL_BINARY_VERSION}.tar.gz"
    NIMBUS_ETH2_TARBALL_URL="https://github.com/status-im/nimbus-eth2/releases/download/v${NIMBUS_ETH2_VERSION}/${NIMBUS_ETH2_TARBALL_NAME}"

    log "Downloading Nimbus ETH2 binary"
    "${CURL_BINARY}" -o "$NIMBUS_ETH2_TARBALL_NAME" -sSL "$NIMBUS_ETH2_TARBALL_URL"
    local tmp_extract_dir
    tmp_extract_dir=$(mktemp -d nimbus-eth2-tarball-XXX)
    CLEANUP_DIRS+=("$tmp_extract_dir")
    tar -xzf "${NIMBUS_ETH2_TARBALL_NAME}" -C "$tmp_extract_dir" --strip-components=1
    mkdir -p "$(dirname "$BEACON_NODE_COMMAND")"
    mv "$tmp_extract_dir/build/nimbus_beacon_node$EXE_EXTENSION" "$BEACON_NODE_COMMAND"
    chmod +x "$BEACON_NODE_COMMAND"
    patchelf_when_on_nixos "$BEACON_NODE_COMMAND"

    REUSE_BINARIES=1
  fi
}

# Download the Lighthouse binary.
LH_VERSION="2.1.3"
LH_ARCH="${ARCH}"
if [[ "${LH_ARCH}" == "arm64" ]]; then
  LH_ARCH="aarch64"
fi

case "${OS}" in
  linux)
    LH_TARBALL="lighthouse-v${LH_VERSION}-${LH_ARCH}-unknown-linux-gnu-portable.tar.gz"
    ;;
  macos)
    LH_TARBALL="lighthouse-v${LH_VERSION}-${LH_ARCH}-apple-darwin-portable.tar.gz"
    ;;
  windows)
    LH_TARBALL="lighthouse-v${LH_VERSION}-${LH_ARCH}-windows-portable.tar.gz"
    ;;
esac
LH_URL="https://github.com/sigp/lighthouse/releases/download/v${LH_VERSION}/${LH_TARBALL}"
LH_BINARY="lighthouse-${LH_VERSION}${EXE_EXTENSION}"

if [[ "${USE_VC}" == "1" && "${LIGHTHOUSE_VC_NODES}" != "0" && ! -e "build/${LH_BINARY}" ]]; then
  echo "Downloading Lighthouse binary"
  pushd "build" >/dev/null
  "${CURL_BINARY}" -sSLO "${LH_URL}"
  tar -xzf "${LH_TARBALL}" # contains just one file named "lighthouse"
  rm lighthouse-* # deletes both the tarball and old binary versions
  mv "lighthouse$EXE_EXTENSION" "${LH_BINARY}"
  popd >/dev/null
fi

BINARIES="ncli_testnet"

if [[ "$LC_NODES" -ge "1" ]]; then
  BINARIES="${BINARIES} nimbus_light_client"
fi

if [[ "$SIGNER_NODES" -gt "0" ]]; then
  if [[ "$SIGNER_TYPE" == "nimbus" ]]; then
    BINARIES="${BINARIES} nimbus_signing_node"
  elif [[ "$SIGNER_TYPE" == "web3signer" ]]; then
    download_web3signer
  fi
fi

# Don't build binaries if we are downloading them
if [[ "${DL_NIMBUS_ETH2}" != "1" ]]; then
  # Build the binaries

  if [[ "${USE_VC}" == "1" ]]; then
    BINARIES="${BINARIES} nimbus_validator_client"
  fi

  BINARIES="${BINARIES} nimbus_beacon_node"
fi

if [[ -n "${ETH2_DOCKER_IMAGE}" ]]; then
  DATA_DIR_FULL_PATH="$(cd "${DATA_DIR}"; pwd)"
  # CONTAINER_DATA_DIR must be used everywhere where paths are supplied to BEACON_NODE_COMMAND executions.
  # We'll use the CONTAINER_ prefix throughout the file to indicate such paths.
  CONTAINER_DATA_DIR="/home/user/nimbus-eth2/testnet"
  BEACON_NODE_COMMAND="docker run -v /etc/passwd:/etc/passwd -u $(id -u):$(id -g) --net=host -v ${DATA_DIR_FULL_PATH}:${CONTAINER_DATA_DIR}:rw $ETH2_DOCKER_IMAGE"
else
  # When docker is not used CONTAINER_DATA_DIR is just an alias for DATA_DIR
  CONTAINER_DATA_DIR="${DATA_DIR}"
  if [[ "${DL_NIMBUS_ETH2}" == "1" ]]; then
    download_nimbus_eth2
  fi
fi

BINARIES_MISSING="0"
for BINARY in ${BINARIES}; do
  if [[ ! -e "build/${BINARY}" ]]; then
    log "Missing binary build/${BINARY}"
    BINARIES_MISSING="1"
    break
  fi
done

if [[ "${REUSE_BINARIES}" == "0" || "${BINARIES_MISSING}" == "1" ]]; then
  log "Rebuilding binaries ${BINARIES}"
  ${MAKE} -j ${NPROC} LOG_LEVEL=TRACE NIMFLAGS="${NIMFLAGS} -d:local_testnet -d:const_preset=${CONST_PRESET} -d:FIELD_ELEMENTS_PER_BLOB=4096" ${BINARIES}
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  if [[ "${DL_NIMBUS_ETH1}" == "1" ]]; then
    download_nimbus_eth1
  fi
fi

# Kill child processes on Ctrl-C/SIGTERM/exit, passing the PID of this shell
# instance as the parent and the target process name as a pattern to the
# "pkill" command.
cleanup() {
  echo "Current port usage:"
  lsof -i -P | grep LISTEN

  echo "Cleaning up"

  # Avoid the trap enterring an infinite loop
  trap - SIGINT SIGTERM EXIT

  PKILL_ECHO_FLAG='-e'
  if [[ "${OS}" == "macos" ]]; then
    PKILL_ECHO_FLAG='-l'
  fi

  PIDS_TO_KILL=$(find "${DATA_DIR}/pids" -type f -exec cat {} \+ 2>/dev/null)

  echo Terminating processes...
  for PID in $PIDS_TO_KILL; do
    kill -SIGTERM $PID 2>/dev/null || true
  done

  sleep 2

  echo Killing processes...
  for PID in $PIDS_TO_KILL; do
    kill -SIGKILL $PID 2>/dev/null || true
  done

  # Delete all binaries we just built, because these are unusable outside this
  # local testnet.
  if [[ "${REUSE_BINARIES}" == "0" ]]; then
    for BINARY in ${BINARIES}; do
      rm -f build/${BINARY}
    done
  fi

  if [[ -n "$ETH2_DOCKER_IMAGE" ]]; then
    docker rm $(docker stop $(docker ps -a -q --filter ancestor=$ETH2_DOCKER_IMAGE --format="{{.ID}}"))
  fi

  if [ ${#CLEANUP_DIRS[@]} -ne 0 ]; then # check if the array is empty
    for dir in "${CLEANUP_DIRS[@]}"
    do
      log "Deleting ${dir}"
      rm -rf "${dir}"
    done
  fi

  echo "Jobs status after cleanup:"
  jobs
}

trap 'cleanup' SIGINT SIGTERM EXIT

# timeout - implemented with a background job
timeout_reached() {
  echo -e "\nTimeout reached. Aborting.\n"
  cleanup
}
trap 'timeout_reached' SIGALRM

if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
  export PARENT_PID=$$
  ( sleep ${TIMEOUT_DURATION} && kill -ALRM ${PARENT_PID} ) 2>/dev/null & WATCHER_PID=$!
fi

REMOTE_URLS=""

for NUM_REMOTE in $(seq 0 $LAST_SIGNER_NODE_IDX); do
  REMOTE_PORT=$(( BASE_REMOTE_SIGNER_PORT + NUM_REMOTE ))
  REMOTE_URLS="${REMOTE_URLS} --remote-signer=http://127.0.0.1:${REMOTE_PORT}"
done

# deposit and testnet creation
BOOTSTRAP_TIMEOUT=30 # in seconds
RUNTIME_CONFIG_FILE="${DATA_DIR}/config.yaml"
NUM_JOBS=${NUM_NODES}

DEPOSITS_FILE="${DATA_DIR}/deposits.json"
CONTAINER_DEPOSITS_FILE="${CONTAINER_DATA_DIR}/deposits.json"
CONTAINER_DEPOSIT_TREE_SNAPSHOT_FILE="${CONTAINER_DATA_DIR}/deposit_tree_snapshot.ssz"

CONTAINER_BOOTSTRAP_NETWORK_KEYFILE="bootstrap_network_key.json"
DIRECTPEER_NETWORK_KEYFILE="directpeer_network_key.json"


BOOTSTRAP_NODE=1
DIRECTPEER_NODE=2

if command -v ulimit; then
  echo "Raising limits"
  ulimit -n $((TOTAL_VALIDATORS * 10))
fi

if [[ "$REUSE_EXISTING_DATA_DIR" == "0" ]]; then
  ./build/ncli_testnet generateDeposits \
    --count=${TOTAL_VALIDATORS} \
    --out-validators-dir="${VALIDATORS_DIR}" \
    --out-secrets-dir="${SECRETS_DIR}" \
    --out-deposits-file="${DEPOSITS_FILE}" \
    --threshold=${REMOTE_SIGNER_THRESHOLD} \
    --remote-validators-count=${REMOTE_VALIDATORS_COUNT} \
    ${REMOTE_URLS}
fi

GENESIS_OFFSET=60  # See `Scheduling first slot action` > `startTime`
NOW_UNIX_TIMESTAMP=$(date +%s)
GENESIS_TIME=$((NOW_UNIX_TIMESTAMP + GENESIS_OFFSET))
SHANGHAI_FORK_TIME=$((GENESIS_TIME + SECONDS_PER_SLOT * SLOTS_PER_EPOCH * CAPELLA_FORK_EPOCH))
CANCUN_FORK_TIME=$((GENESIS_TIME + SECONDS_PER_SLOT * SLOTS_PER_EPOCH * DENEB_FORK_EPOCH))

EXECUTION_GENESIS_JSON="${DATA_DIR}/execution_genesis.json"
EXECUTION_GENESIS_BLOCK_JSON="${DATA_DIR}/execution_genesis_block.json"

# TODO The storage state of the deposit contract that is baked into the execution genesis state
#      currently hard-codes some merkle branches that won't match the random deposits generated
#      by this simulation. This doesn't happen to produce problems only by accident. If we enable
#      the `deposit_root` safety-checks in the deposit downloader, it will detect the discrepancy.
sed "s/SHANGHAI_FORK_TIME/${SHANGHAI_FORK_TIME}/g; s/CANCUN_FORK_TIME/${CANCUN_FORK_TIME}/g" \
  "${SCRIPTS_DIR}/execution_genesis.json.template" > "$EXECUTION_GENESIS_JSON"

DEPOSIT_CONTRACT_ADDRESS="0x4242424242424242424242424242424242424242"
DEPOSIT_CONTRACT_BLOCK=0

get_execution_genesis_block() {
  ${CURL_BINARY} -s -X POST \
      -H 'Content-Type: application/json' \
      --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest", true],"id":1}' \
      $1 | jq '.result'
}

if [[ "${RUN_GETH}" == "1" ]]; then
  if [[ ! -e "${GETH_BINARY}" ]]; then
    echo "Missing geth executable"
    exit 1
  fi

  source "./scripts/start_geth_nodes.sh"

  CLEANUP_DIRS+=("${GETH_DATA_DIRS[@]}")
  MAIN_WEB3_URL="http://127.0.0.1:${GETH_RPC_PORTS[0]}"
  get_execution_genesis_block "${MAIN_WEB3_URL}" >  "$EXECUTION_GENESIS_BLOCK_JSON"
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  if [[ ! -e "${NIMBUS_ETH1_BINARY}" ]]; then
    echo "Missing nimbus EL executable"
    exit 1
  fi

  source "./scripts/start_nimbus_el_nodes.sh"

  CLEANUP_DIRS+=("${NIMBUS_ETH1_DATA_DIRS[@]}")

  MAIN_WEB3_URL="http://127.0.0.1:${NIMBUS_ETH1_RPC_PORTS[0]}"
  get_execution_genesis_block "$MAIN_WEB3_URL" > "$EXECUTION_GENESIS_BLOCK_JSON.nimbus"
  if [ -f "$EXECUTION_GENESIS_BLOCK_JSON" ]; then
    if ! cmp <(jq --compact-output --sort-keys . "$EXECUTION_GENESIS_BLOCK_JSON") <(jq --compact-output --sort-keys . "$EXECUTION_GENESIS_BLOCK_JSON.nimbus"); then
      echo "Nimbus and Geth disagree regarding the genesis execution block"
      exit 1
    fi
  else
    mv "$EXECUTION_GENESIS_BLOCK_JSON.nimbus" "$EXECUTION_GENESIS_BLOCK_JSON"
  fi
fi

jq -r '.hash' "$EXECUTION_GENESIS_BLOCK_JSON" > "${DATA_DIR}/deposit_contract_block_hash.txt"

for NUM_NODE in $(seq 1 $NUM_NODES); do
  NODE_DATA_DIR="${DATA_DIR}/node${NUM_NODE}"
  rm -rf "${NODE_DATA_DIR}"
  scripts/makedir.sh "${NODE_DATA_DIR}" 2>&1
done

./build/ncli_testnet createTestnet \
  --data-dir="$CONTAINER_DATA_DIR/node$BOOTSTRAP_NODE" \
  --deposits-file="$CONTAINER_DEPOSITS_FILE" \
  --total-validators=$TOTAL_VALIDATORS \
  --output-genesis="$CONTAINER_DATA_DIR/genesis.ssz" \
  --output-bootstrap-file="$CONTAINER_DATA_DIR/bootstrap_nodes.txt" \
  --output-deposit-tree-snapshot="$CONTAINER_DEPOSIT_TREE_SNAPSHOT_FILE" \
  --bootstrap-address=127.0.0.1 \
  --bootstrap-port=$(( BASE_PORT + BOOTSTRAP_NODE - 1 )) \
  --netkey-file=$CONTAINER_BOOTSTRAP_NETWORK_KEYFILE \
  --insecure-netkey-password=true \
  --genesis-time=$GENESIS_TIME \
  --capella-fork-epoch=$CAPELLA_FORK_EPOCH \
  --deneb-fork-epoch=$DENEB_FORK_EPOCH \
  --execution-genesis-block="$EXECUTION_GENESIS_BLOCK_JSON"

DIRECTPEER_ENR=$(
  ./build/ncli_testnet createTestnetEnr \
    --data-dir="$CONTAINER_DATA_DIR/node$DIRECTPEER_NODE" \
    --bootstrap-enr="$CONTAINER_DATA_DIR/bootstrap_nodes.txt" \
    --enr-address=127.0.0.1 \
    --enr-port=$(( BASE_PORT + DIRECTPEER_NODE - 1 )) \
    --enr-netkey-file=$DIRECTPEER_NETWORK_KEYFILE \
    --insecure-netkey-password=true 2>&1 > /dev/null
)

./scripts/make_prometheus_config.sh \
    --nodes ${NUM_NODES} \
    --base-metrics-port ${BASE_METRICS_PORT} \
    --config-file "${DATA_DIR}/prometheus.yml" || true # TODO: this currently fails on macOS,
                                                       # but it can be considered non-critical

cp "$SCRIPTS_DIR/$CONST_PRESET-non-overriden-config.yaml" "$RUNTIME_CONFIG_FILE"
# TODO the runtime config file should be used during deposit generation as well!
echo Wrote $RUNTIME_CONFIG_FILE:
tee -a "$RUNTIME_CONFIG_FILE" <<EOF
PRESET_BASE: ${CONST_PRESET}
MIN_GENESIS_ACTIVE_VALIDATOR_COUNT: ${TOTAL_VALIDATORS}
MIN_GENESIS_TIME: 0
GENESIS_DELAY: 10
DEPOSIT_CONTRACT_ADDRESS: ${DEPOSIT_CONTRACT_ADDRESS}
ETH1_FOLLOW_DISTANCE: 1
ALTAIR_FORK_EPOCH: 0
BELLATRIX_FORK_EPOCH: 0
CAPELLA_FORK_EPOCH: ${CAPELLA_FORK_EPOCH}
DENEB_FORK_EPOCH: ${DENEB_FORK_EPOCH}
TERMINAL_TOTAL_DIFFICULTY: 0
EOF

echo $DEPOSIT_CONTRACT_BLOCK > "${DATA_DIR}/deposit_contract_block.txt"

if [[ "${LIGHTHOUSE_VC_NODES}" != "0" ]]; then
  # I don't know what this is, but Lighthouse wants it, so we recreate it from
  # Lighthouse's own local testnet.
  echo $DEPOSIT_CONTRACT_BLOCK > "${DATA_DIR}/deploy_block.txt"
fi

dump_logs() {
  LOG_LINES=50
  for LOG in "${DATA_DIR}"/logs/*; do
    echo "Last ${LOG_LINES} lines of ${LOG}:"
    tail -n ${LOG_LINES} "${LOG}"
    echo "======"
  done
}

dump_logtrace() {
  if [[ "$ENABLE_LOGTRACE" == "1" ]]; then
    find "${DATA_DIR}/logs" -maxdepth 1 -type f -regex 'nimbus_beacon_node[0-9]+.jsonl' | sed -e"s/${DATA_DIR}\//--nodes=/" | sort | xargs ./build/ncli_testnet analyzeLogs --log-dir="${DATA_DIR}" --const-preset=${CONST_PRESET} || true
  fi
}

NODES_WITH_VALIDATORS=${NODES_WITH_VALIDATORS:-$NUM_NODES}
SYSTEM_VALIDATORS=$(( TOTAL_VALIDATORS - USER_VALIDATORS ))
VALIDATORS_PER_NODE=$(( SYSTEM_VALIDATORS / NODES_WITH_VALIDATORS ))
if [[ "${USE_VC}" == "1" ]]; then
  # if using validator client binaries in addition to beacon nodes we will
  # split the keys for this instance in half between the BN and the VC
  # and the validators for the BNs will be from the first half of all validators
  VALIDATORS_PER_NODE=$(( VALIDATORS_PER_NODE / 2 ))
  NUM_JOBS=$(( NUM_JOBS * 2 ))
fi

if [[ "$SIGNER_NODES" -ge "0" ]]; then
  NUM_JOBS=$(( NUM_JOBS + SIGNER_NODES ))
fi

if [[ "$LC_NODES" -ge "1" ]]; then
  NUM_JOBS=$(( NUM_JOBS + LC_NODES ))
fi

if [[ "${RUN_GETH}" == "1" ]]; then
  NUM_JOBS=$(( NUM_JOBS + GETH_NUM_NODES ))
fi

if [[ "${RUN_NIMBUS_ETH1}" == "1" ]]; then
  NUM_JOBS=$(( NUM_JOBS + NIMBUS_ETH1_NUM_NODES ))
fi

VALIDATORS_PER_VALIDATOR=$(( (SYSTEM_VALIDATORS / NODES_WITH_VALIDATORS) / 2 ))
VALIDATOR_OFFSET=$(( SYSTEM_VALIDATORS / 2 ))

BOOTSTRAP_ENR="${DATA_DIR}/node${BOOTSTRAP_NODE}/beacon_node.enr"
CONTAINER_BOOTSTRAP_ENR="${CONTAINER_DATA_DIR}/node${BOOTSTRAP_NODE}/beacon_node.enr"

# TODO The deposit generator tool needs to gain support for generating two sets
#      of deposits (genesis + submitted ones). Then we can enable the sending of
#      deposits here.
#
#./build/ncli_testnet sendDeposits \
#  --deposits-file="$DEPOSITS_FILE" \
#  --min-delay=$MIN_DEPOSIT_SENDING_DELAY --max-delay=$MAX_DEPOSIT_SENDING_DELAY \
#  --web3-url="$MAIN_WEB3_URL" \
#  --deposit-contract=$DEPOSIT_CONTRACT_ADDRESS > "$DATA_DIR/log_deposit_maker.txt" 2>&1 &

for NUM_NODE in $(seq 1 $NUM_NODES); do
  # Copy validators to individual nodes.
  # The first $NODES_WITH_VALIDATORS nodes split them equally between them,
  # after skipping the first $USER_VALIDATORS.
  NODE_DATA_DIR="${DATA_DIR}/node${NUM_NODE}"
  scripts/makedir.sh "${NODE_DATA_DIR}/validators" 2>&1
  scripts/makedir.sh "${NODE_DATA_DIR}/secrets" 2>&1

  if [[ $NUM_NODE -le $NODES_WITH_VALIDATORS ]]; then
    if [[ "${USE_VC}" == "1" ]]; then
      VALIDATOR_DATA_DIR="${DATA_DIR}/validator${NUM_NODE}"
      rm -rf "${VALIDATOR_DATA_DIR}"
      scripts/makedir.sh "${VALIDATOR_DATA_DIR}" 2>&1
      scripts/makedir.sh "${VALIDATOR_DATA_DIR}/validators" 2>&1
      scripts/makedir.sh "${VALIDATOR_DATA_DIR}/secrets" 2>&1
      for VALIDATOR in $(ls "${VALIDATORS_DIR}" | tail -n +$(( USER_VALIDATORS + (VALIDATORS_PER_VALIDATOR * (NUM_NODE - 1)) + 1 + VALIDATOR_OFFSET )) | head -n $VALIDATORS_PER_VALIDATOR); do
        cp -a "${VALIDATORS_DIR}/${VALIDATOR}" "${VALIDATOR_DATA_DIR}/validators/" 2>&1
        # Remote validators won't have a secret file
        if [ -f "${SECRETS_DIR}/${VALIDATOR}" ]; then
          cp -a "${SECRETS_DIR}/${VALIDATOR}" "${VALIDATOR_DATA_DIR}/secrets/" 2>&1
        fi
      done
      if [[ "${OS}" == "Windows_NT" ]]; then
        find "${VALIDATOR_DATA_DIR}" -type f \( -iname "*.json" -o ! -iname "*.*" \) -exec icacls "{}" /inheritance:r /grant:r ${USERDOMAIN}\\${USERNAME}:\(F\) \;
      fi
    fi
    for VALIDATOR in $(ls "${VALIDATORS_DIR}" | tail -n +$(( USER_VALIDATORS + (VALIDATORS_PER_NODE * (NUM_NODE - 1)) + 1 )) | head -n $VALIDATORS_PER_NODE); do
      cp -a "${VALIDATORS_DIR}/${VALIDATOR}" "${NODE_DATA_DIR}/validators/" 2>&1
      if [[ -f "${VALIDATORS_DIR}/${VALIDATOR}/keystore.json" ]]; then
        # Only remote key stores doesn't have a secret
        cp -a "${SECRETS_DIR}/${VALIDATOR}" "${NODE_DATA_DIR}/secrets/" 2>&1
      fi
    done
    if [[ "${OS}" == "Windows_NT" ]]; then
      find "${NODE_DATA_DIR}" -type f \( -iname "*.json" -o ! -iname "*.*" \) -exec icacls "{}" /inheritance:r /grant:r ${USERDOMAIN}\\${USERNAME}:\(F\) \;
    fi
  fi
done

for NUM_LC in $(seq 1 $LC_NODES); do
  LC_DATA_DIR="${DATA_DIR}/lc${NUM_LC}"
  rm -rf "${LC_DATA_DIR}"
  scripts/makedir.sh "${LC_DATA_DIR}" 2>&1
done

CLI_CONF_FILE="$CONTAINER_DATA_DIR/config.toml"

cat > "$CLI_CONF_FILE" <<END_CLI_CONFIG
non-interactive = true
nat = "extip:127.0.0.1"
network = "${CONTAINER_DATA_DIR}"
log-level = "${LOG_LEVEL}"
log-format = "json"
rest = true
rest-address = "127.0.0.1"
metrics = true
metrics-address = "127.0.0.1"
END_CLI_CONFIG

# Export some variables that can be used by the signer launch scripts
export DATA_DIR
export BASE_REMOTE_SIGNER_PORT
export WEB3SIGNER_BINARY
export RUNTIME_CONFIG_FILE

# https://ss64.com/osx/seq.html documents that at macOS seq(1) counts backwards
# as probably do some others
if ((SIGNER_NODES > 0)); then
  for NUM_REMOTE in $(seq 0 $LAST_SIGNER_NODE_IDX); do
    # TODO find some way for this and other background-launched processes to
    # still participate in set -e, ideally
    source "${SCRIPTS_DIR}/signers/${SIGNER_TYPE}.sh" $NUM_REMOTE
  done
fi

# give each node time to load keys
sleep 10

for NUM_NODE in $(seq 1 $NUM_NODES); do
  NODE_DATA_DIR="${DATA_DIR}/node${NUM_NODE}"
  CONTAINER_NODE_DATA_DIR="${CONTAINER_DATA_DIR}/node${NUM_NODE}"
  VALIDATOR_DATA_DIR="${DATA_DIR}/validator${NUM_NODE}"
  if [[ ${NUM_NODE} == ${BOOTSTRAP_NODE} ]]; then
    # Due to star topology, the bootstrap node must relay all attestations,
    # even if it itself is not interested. --subscribe-all-subnets could be
    # removed by switching to a fully-connected topology.
    BOOTSTRAP_ARG="--netkey-file=${CONTAINER_BOOTSTRAP_NETWORK_KEYFILE} --insecure-netkey-password=true --subscribe-all-subnets --direct-peer=$DIRECTPEER_ENR"
  elif [[ ${NUM_NODE} == ${DIRECTPEER_NODE} ]]; then
    # Start a node using the Direct Peer functionality instead of regular bootstraping
    BOOTSTRAP_ARG="--netkey-file=${DIRECTPEER_NETWORK_KEYFILE} --direct-peer=$(cat $CONTAINER_BOOTSTRAP_ENR) --insecure-netkey-password=true"
  else
    BOOTSTRAP_ARG="--bootstrap-file=${CONTAINER_BOOTSTRAP_ENR}"
  fi

  if [[ ${NUM_NODE} != ${BOOTSTRAP_NODE} ]]; then
    if [[ "${CONST_PRESET}" == "minimal" ]]; then
      # The fast epoch and slot times in the minimal config might cause the
      # mesh to break down due to re-subscriptions happening within the prune
      # backoff time
      BOOTSTRAP_ARG="${BOOTSTRAP_ARG} --subscribe-all-subnets"
    fi
  fi

  WEB3_ARG=()
  if [ "${RUN_NIMBUS_ETH1}" == "1" ]; then
    WEB3_ARG+=("--web3-url=http://127.0.0.1:${NIMBUS_ETH1_RPC_PORTS[$(( NUM_NODE - 1 ))]}")
  fi

  if [ "${RUN_GETH}" == "1" ]; then
    WEB3_ARG+=("--web3-url=http://127.0.0.1:${GETH_AUTH_RPC_PORTS[$((NUM_NODE - 1))]}")
  fi

  if [ ${#WEB3_ARG[@]} -eq 0 ]; then # check if the array is empty
    WEB3_ARG=("--require-engine-api-in-bellatrix=no")
  fi

  # We enabled the keymanager on half of the nodes in order
  # to make sure that the client can work without it.
  KEYMANAGER_FLAG=""
  if [ $((NUM_NODE % 2)) -eq 0 ]; then
    KEYMANAGER_FLAG="--keymanager"
  fi

  ${BEACON_NODE_COMMAND} \
    --config-file="${CLI_CONF_FILE}" \
    --tcp-port=$(( BASE_PORT + NUM_NODE - 1 )) \
    --udp-port=$(( BASE_PORT + NUM_NODE - 1 )) \
    --max-peers=$(( NUM_NODES + LC_NODES - 1 )) \
    --data-dir="${CONTAINER_NODE_DATA_DIR}" \
    ${BOOTSTRAP_ARG} \
    --jwt-secret=${JWT_FILE} \
    "${WEB3_ARG[@]}" \
    --payload-builder=${USE_PAYLOAD_BUILDER} \
    --payload-builder-url="http://${PAYLOAD_BUILDER_HOST}:${PAYLOAD_BUILDER_PORT}" \
    --light-client-data-serve=on \
    --light-client-data-import-mode=full \
    --light-client-data-max-periods=999999 \
    ${STOP_AT_EPOCH_FLAG} \
    ${KEYMANAGER_FLAG} \
    --keymanager-token-file="${DATA_DIR}/keymanager-token" \
    --finalized-deposit-tree-snapshot="$CONTAINER_DEPOSIT_TREE_SNAPSHOT_FILE" \
    --rest-port="$(( BASE_REST_PORT + NUM_NODE - 1 ))" \
    --metrics-port="$(( BASE_METRICS_PORT + NUM_NODE - 1 ))" \
    --doppelganger-detection=off \
    ${EXTRA_ARGS} \
    &> "${DATA_DIR}/logs/nimbus_beacon_node.${NUM_NODE}.jsonl" &
  PID=$!
  PIDS_TO_WAIT="${PIDS_TO_WAIT},$!"
  echo $PID > "$DATA_DIR/pids/nimbus_beacon_node.${NUM_NODE}"

  if [[ "${USE_VC}" == "1" ]]; then
    if [[ "${LIGHTHOUSE_VC_NODES}" -ge "${NUM_NODE}" ]]; then
      # Lighthouse needs a different keystore filename for its auto-discovery process.
      for D in "${VALIDATOR_DATA_DIR}/validators"/0x*; do
        if [[ -e "${D}/keystore.json" ]]; then
          mv "${D}/keystore.json" "${D}/voting-keystore.json"
        fi
      done

      ./build/${LH_BINARY} vc \
        --debug-level "debug" \
        --logfile-max-number 0 \
        --log-format "JSON" \
        --validators-dir "${VALIDATOR_DATA_DIR}" \
        --secrets-dir "${VALIDATOR_DATA_DIR}/secrets" \
        --beacon-nodes "http://127.0.0.1:$((BASE_REST_PORT + NUM_NODE))" \
        --testnet-dir "${DATA_DIR}" \
        --init-slashing-protection \
        &> "${DATA_DIR}/logs/lighthouse_vc.${NUM_NODE}.txt" &
      echo $! > "$DATA_DIR/pids/lighthouse_vc.${NUM_NODE}"
    else
      ./build/nimbus_validator_client \
        --log-level="${LOG_LEVEL}" \
        ${STOP_AT_EPOCH_FLAG} \
        --data-dir="${VALIDATOR_DATA_DIR}" \
        --metrics \
        --metrics-port=$(( BASE_VC_METRICS_PORT + NUM_NODE - 1 )) \
        --payload-builder=${USE_PAYLOAD_BUILDER} \
        ${KEYMANAGER_FLAG} \
        --keymanager-port=$(( BASE_VC_KEYMANAGER_PORT + NUM_NODE - 1 )) \
        --keymanager-token-file="${DATA_DIR}/keymanager-token" \
        --beacon-node="http://127.0.0.1:$(( BASE_REST_PORT + NUM_NODE - 1 ))" \
        &> "${DATA_DIR}/logs/nimbus_validator_client.${NUM_NODE}.jsonl" &
      PID=$!
      PIDS_TO_WAIT="${PIDS_TO_WAIT},$PID"
      echo $PID > "$DATA_DIR/pids/nimbus_validator_client.${NUM_NODE}"
    fi
  fi

  # Wait for the master node to write out its address file
  START_TIMESTAMP=$(date +%s)
  while [[ ! -f "${BOOTSTRAP_ENR}" ]]; do
    sleep 0.1
    NOW_TIMESTAMP=$(date +%s)
    if [[ "$(( NOW_TIMESTAMP - START_TIMESTAMP - GENESIS_OFFSET ))" -ge "$BOOTSTRAP_TIMEOUT" ]]; then
      echo "Bootstrap node failed to start in ${BOOTSTRAP_TIMEOUT} seconds. Aborting."
      dump_logs
      exit 1
    fi
  done
done

# light clients
if [ "$LC_NODES" -ge "1" ]; then
  echo "Waiting for Altair finalization"
  while :; do
    BN_ALTAIR_FORK_EPOCH="$(
      "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/config/spec" | \
        "${JQ_BINARY}" -r '.data.ALTAIR_FORK_EPOCH')"
    if [ "${BN_ALTAIR_FORK_EPOCH}" -eq "${BN_ALTAIR_FORK_EPOCH}" ]; then # check for number
      break
    fi
    echo "ALTAIR_FORK_EPOCH: ${BN_ALTAIR_FORK_EPOCH}"
    sleep 1
  done
  while :; do
    CURRENT_FORK_EPOCH="$(
      "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/beacon/states/finalized/fork" | \
      "${JQ_BINARY}" -r '.data.epoch')"
    if [ "${CURRENT_FORK_EPOCH}" -ge "${BN_ALTAIR_FORK_EPOCH}" ]; then
      break
    fi
    sleep 1
  done

  log "After ALTAIR_FORK_EPOCH"

  echo "Altair finalized, launching $LC_NODES light client(s)"
  LC_BOOTSTRAP_NODE="$(
    "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/node/identity" | \
      "${JQ_BINARY}" -r '.data.enr')"
  LC_TRUSTED_BLOCK_ROOT="$(
    "${CURL_BINARY}" -s "http://localhost:${BASE_REST_PORT}/eth/v1/beacon/headers/finalized" | \
      "${JQ_BINARY}" -r '.data.root')"
  for NUM_LC in $(seq 1 $LC_NODES); do
    LC_DATA_DIR="${DATA_DIR}/lc${NUM_LC}"

    WEB3_ARG=()
    if [ "${RUN_NIMBUS_ETH1}" == "1" ]; then
      WEB3_ARG+=("--web3-url=http://127.0.0.1:${NIMBUS_ETH1_RPC_PORTS[$(( NUM_NODES + NUM_LC - 1 ))]}")
    fi

    if [ "${RUN_GETH}" == "1" ]; then
      WEB3_ARG+=("--web3-url=http://127.0.0.1:${GETH_AUTH_RPC_PORTS[$(( NUM_NODES + NUM_LC - 1 ))]}")
    fi

    ./build/nimbus_light_client \
      --log-level="${LOG_LEVEL}" \
      --log-format="json" \
      --data-dir="${LC_DATA_DIR}" \
      --network="${CONTAINER_DATA_DIR}" \
      --bootstrap-node="${LC_BOOTSTRAP_NODE}" \
      --tcp-port=$(( BASE_PORT + NUM_NODES + NUM_LC - 1 )) \
      --udp-port=$(( BASE_PORT + NUM_NODES + NUM_LC - 1 )) \
      --max-peers=$(( NUM_NODES + LC_NODES - 1 )) \
      --nat="extip:127.0.0.1" \
      --trusted-block-root="${LC_TRUSTED_BLOCK_ROOT}" \
      --jwt-secret="${JWT_FILE}" \
      "${WEB3_ARG[@]}" \
      ${STOP_AT_EPOCH_FLAG} \
      &> "${DATA_DIR}/logs/nimbus_light_client.${NUM_LC}.jsonl" &
    PID=$!
    PIDS_TO_WAIT="${PIDS_TO_WAIT},${PID}"
    echo $PID > "${DATA_DIR}/pids/nimbus_light_client.${NUM_LC}"
  done
fi

# give the regular nodes time to crash
sleep 5
BG_JOBS="$(jobs | wc -l | tr -d ' ')"
if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
  BG_JOBS=$(( BG_JOBS - 1 )) # minus the timeout bg job
fi

if [[ "$BG_JOBS" != "$NUM_JOBS" ]]; then
  echo "$(( NUM_JOBS - BG_JOBS )) nimbus_beacon_node/nimbus_validator_client/nimbus_light_client instance(s) exited early. Aborting."
  dump_logs
  dump_logtrace
  exit 1
fi

echo "About to wait for the following sub-processes: " $PIDS_TO_WAIT

# launch "htop" or wait for background jobs
if [[ "$USE_HTOP" == "1" ]]; then
  htop -p "$PIDS_TO_WAIT"
  # Cleanup is done when this script exists, since we listen to the EXIT signal.
else
  FAILED=0
  for PID in $(echo "$PIDS_TO_WAIT" | tr ',' ' '); do
    wait "$PID" || FAILED="$(( FAILED += 1 ))"
    echo $PID has completed
  done
  if [[ "$FAILED" != "0" ]]; then
    echo "${FAILED} child processes had non-zero exit codes (or exited early)."
    dump_logs
    dump_logtrace
    if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
      if uname | grep -qiE "mingw|msys"; then
        taskkill //F //PID ${WATCHER_PID}
      else
        pkill -HUP -P ${WATCHER_PID}
      fi
    fi
    exit 1
  fi
fi

dump_logtrace

if [[ "${TIMEOUT_DURATION}" != "0" ]]; then
  if uname | grep -qiE "mingw|msys"; then
    taskkill //F //PID ${WATCHER_PID}
  else
    pkill -HUP -P ${WATCHER_PID}
  fi
fi

echo The simulation completed successfully
exit 0
