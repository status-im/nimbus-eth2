#!/bin/bash

cd "$(dirname $0)"
scripts/run-beacon-node.sh beacon_node mainnet $@

