#!/bin/bash

set -e
cd $(dirname "$0")

set -a
source $1.env
set +a

NIM_FLAGS=""

add_var () {
  if [[ ! -z "${!1}" ]]; then
    NIM_FLAGS+="-d:$1=${!1} "
  fi
}

add_var CONST_PRESET
add_var NETWORK_TYPE
add_var SLOTS_PER_EPOCH
add_var MAX_COMMITTEES_PER_SLOT

echo $NIM_FLAGS

