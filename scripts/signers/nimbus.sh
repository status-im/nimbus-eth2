#!/usr/bin/env bash

# Copyright (c) 2023 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

SIGNING_NODE_IDX=$1

./build/nimbus_signing_node \
  --log-level=DEBUG \
  --validators-dir="${DATA_DIR}/validators_shares/$(( SIGNING_NODE_IDX + 1 ))" \
  --secrets-dir="${DATA_DIR}/secrets_shares/$(( SIGNING_NODE_IDX + 1 ))" \
  --bind-port=$(( BASE_REMOTE_SIGNER_PORT + SIGNING_NODE_IDX )) &> "${DATA_DIR}/logs/nimbus_signing_node.${SIGNING_NODE_IDX}.jsonl" &

echo $! > "${DATA_DIR}/pids/nimbus_signing_node.${SIGNING_NODE_IDX}"
