#!/bin/bash

# Lighthouse genesis state
curl localhost:5052/beacon/state?slot=0 | python -m json.tool | sed 's/"0x/"/' > /tmp/lighthouse_state.json

# Format nimbus the same
cat data/state_snapshot.json | python -m json.tool | sed 's/"0x/"/' > /tmp/nimbus_state.json

diff -uw /tmp/nimbus_state.json /tmp/lighthouse_state.json

