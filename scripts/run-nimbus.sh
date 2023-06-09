#!/usr/bin/env bash

build/nimbus_beacon_node trustedNodeSync --config-file=config.toml

#\
#  --network:mainnet \
#  --data-dir=build/mainnet/nimbus \
#  --backfill=false \
#  --trusted-node-url=http://testing.mainnet.beacon-api.nimbus.team/

if [ ! -f build/mainnet/jwtsecret ]; then
  openssl rand -hex 32 | tr -d "\n" > build/mainnet/jwtsecret
fi

# build/nimbus_beacon_node --non-interactive --udp-port=9123 --tcp-port=9123 --network=mainnet --log-level=DEBUG --data-dir=build/mainnet/nimbus --web3-url=http://localhost:9551/ --rest:on --metrics:on --doppelganger-detection=no --jwt-secret=build/mainnet/jwtsecret
