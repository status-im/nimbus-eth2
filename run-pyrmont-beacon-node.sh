#!/bin/bash

cd "$(dirname $0)"
# Allow the binary to receive signals directly.
exec scripts/run-beacon-node.sh nimbus_beacon_node pyrmont $@

