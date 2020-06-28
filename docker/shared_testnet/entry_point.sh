#!/bin/bash

set -e

cd "$(dirname "${BASH_SOURCE[0]}")"

####################
# argument parsing #
####################
! getopt --test > /dev/null
if [ ${PIPESTATUS[0]} != 4 ]; then
	echo '`getopt --test` failed in this environment.'
	exit 1
fi

OPTS="h"
LONGOPTS="help,build,run"

# default values
BUILD=0
RUN=0

print_help() {
	cat <<EOF
Usage: $(basename $0) <options> -- <beacon_node options>

  -h, --help			this help message
      --build     build the beacon_node
      --run       run the beacon_node
EOF
}

! PARSED=$(getopt --options=${OPTS} --longoptions=${LONGOPTS} --name "$0" -- "$@")
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
    --build)
      BUILD=1
      shift
      ;;
    --run)
      RUN=1
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

# docker-compose.yml inserts newlines in our options
if [[ "$(echo $1 | tr -d '[:space:]')" == "--" ]]; then
  shift
fi

EXTRA_ARGS="$@"

#########
# build #
#########

if [[ "$BUILD" == "1" ]]; then
  # "/root/.cache/nimbus" is the external bind-mounted dir, preserved between runs
  cd /root/.cache/nimbus
  [[ -d nim-beacon-chain ]] || git clone https://github.com/status-im/nim-beacon-chain.git
  cd nim-beacon-chain
  git config pull.rebase false
  git checkout devel
  git pull
  make -j$(nproc) update
  make LOG_LEVEL="TRACE" NIMFLAGS="-d:insecure -d:testnet_servers_image" SCRIPT_PARAMS="--skipGoerliKey --writeLogFile=false --buildOnly" ${NETWORK}
fi

#######
# run #
#######

if [[ "$RUN" == "1" ]]; then
  cd /root/.cache/nimbus/nim-beacon-chain
  echo $(make SCRIPT_PARAMS="--skipGoerliKey --writeLogFile=false --runOnly --printCmdOnly" ${NETWORK} | tail -n 1) ${EXTRA_ARGS}
  # make sure Docker's SIGINT reaches the beacon_node binary
  eval $(make SCRIPT_PARAMS="--skipGoerliKey --writeLogFile=false --runOnly --printCmdOnly" ${NETWORK} | tail -n 1) ${EXTRA_ARGS}
fi

