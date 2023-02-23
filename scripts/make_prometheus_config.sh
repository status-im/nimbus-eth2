#!/usr/bin/env bash

# Copyright (c) 2020 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

set -e

####################
# argument parsing #
####################

GETOPT_BINARY="getopt"
if uname | grep -qi darwin; then
  # macOS
  GETOPT_BINARY=$(find /opt/homebrew/opt/gnu-getopt/bin/getopt /usr/local/opt/gnu-getopt/bin/getopt 2> /dev/null || true)
	[[ -f "$GETOPT_BINARY" ]] || { echo "GNU getopt not installed. Please run 'brew install gnu-getopt'. Aborting."; exit 1; }
fi

! ${GETOPT_BINARY} --test > /dev/null
if [ ${PIPESTATUS[0]} != 4 ]; then
	echo '`getopt --test` failed in this environment.'
	exit 1
fi

OPTS="h"
LONGOPTS="help,nodes:,base-metrics-port:,config-file:"

# default values
NUM_NODES="10"
BASE_METRICS_PORT="8008"
CONFIG_FILE="prometheus.yml"

print_help() {
	cat <<EOF
Usage: $(basename $0) --nodes ${NUM_NODES} --base-metrics-port ${BASE_METRICS_PORT} --config-file "${CONFIG_FILE}"

  -h, --help			this help message
      --nodes			number of nodes to launch (default: ${NUM_NODES})
      --base-metrics-port	bootstrap node's metrics server port (default: ${BASE_METRICS_PORT})
      --config-file		write the Prometheus config to this file (default: ${CONFIG_FILE})
EOF
}

! PARSED=$(${GETOPT_BINARY} --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
if [ ${PIPESTATUS[0]} != 0 ]; then
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
		--base-metrics-port)
			BASE_METRICS_PORT="$2"
			shift 2
			;;
		--config-file)
			CONFIG_FILE="$2"
			shift 2
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

cat > "${CONFIG_FILE}" <<EOF
global:
  scrape_interval: 12s

scrape_configs:
  - job_name: "nimbus"
    static_configs:
EOF
for NUM_NODE in $(seq 1 $NUM_NODES); do
	cat >> "${CONFIG_FILE}" <<EOF
      - targets: ['127.0.0.1:$(( BASE_METRICS_PORT + NUM_NODE ))']
EOF
done

