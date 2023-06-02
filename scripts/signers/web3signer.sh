#!/usr/bin/bash

# Copyright (c) 2023 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

if ! command javac > /dev/null || ! javac -version > /dev/null; then
  # On macOS, homebrew doesn't make java available in your PATH by default.
  # Instead, macOS ships with a stub executable that displays a message that
  # Java is not installed (javac -version exits with an error code 1).
  # If the user is running under these default settings, but a homebrew
  # installation is disovered, we are happy to use it just in this script:
  if [[ -d /opt/homebrew/opt/openjdk/bin ]]; then
    export PATH="/opt/homebrew/opt/openjdk/bin:$PATH"
  fi
fi

WEB3SIGNER_NODE_IDX=$1

SECRETS_DIR="${DATA_DIR}/secrets_shares/$((WEB3SIGNER_NODE_IDX + 1))"
KEYSTORES_DIR="${DATA_DIR}/validators_shares/$((WEB3SIGNER_NODE_IDX + 1))"

# We re-arrange the keystore files to match the layout expected by the Web3Signer
# TODO generateSimulationDeposits can be refactored to produce the right layout from the start
for validator_pubkey in $(ls "$SECRETS_DIR")
do
  mv "$SECRETS_DIR/$validator_pubkey" "$SECRETS_DIR/$validator_pubkey.txt"
  mv "$KEYSTORES_DIR/$validator_pubkey/keystore.json" "$KEYSTORES_DIR/$validator_pubkey.json"
done

# still participate in set -e, ideally
# TODO find some way for this and other background-launched processes to
"${WEB3SIGNER_BINARY}" \
  --http-listen-port=$(( BASE_REMOTE_SIGNER_PORT + WEB3SIGNER_NODE_IDX )) \
  --logging=DEBUG \
  --metrics-enabled=true \
  --metrics-port=$(( BASE_REMOTE_SIGNER_METRICS_PORT + WEB3SIGNER_NODE_IDX )) \
  eth2 \
  --slashing-protection-enabled=false \
  --keystores-passwords-path="${SECRETS_DIR}" \
  --keystores-path="${KEYSTORES_DIR}" \
  --network="${RUNTIME_CONFIG_FILE}" &> "${DATA_DIR}/logs/web3signer.${WEB3SIGNER_NODE_IDX}.log" &

echo $! > "${DATA_DIR}/pids/web3signer.${WEB3SIGNER_NODE_IDX}"
