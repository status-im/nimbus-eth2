set -a
source $1
set +a

TESTNET_NIM_FLAGS=""

testnet_env () {
  eval "TESTNET_FLAG_VALUE=\$$1"
  if [[ ! -z "$TESTNET_FLAG_VALUE" ]]; then
    TESTNET_NIM_FLAGS+=" -d:$1=$TESTNET_FLAG_VALUE"
  fi
}

testnet_env CONST_PRESET
testnet_env NETWORK_TYPE
testnet_env SLOTS_PER_EPOCH
testnet_env SLOTS_PER_EPOCH
testnet_env MAX_COMMITTEES_PER_SLOT

export TESTNET_NIM_FLAGS

