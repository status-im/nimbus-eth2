#!/bin/bash

cd "$(dirname $0)"
scripts/run-beacon-node.sh nimbus_beacon_node_spec_0_12_3 medalla $@

