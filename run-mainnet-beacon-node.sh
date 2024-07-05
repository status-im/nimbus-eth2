#!/usr/bin/env bash

# Copyright (c) 2020-2024 Status Research & Development GmbH. Licensed under
# either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed except
# according to those terms.

cd "$(dirname $0)"
# Allow the binary to receive signals directly.
exec scripts/run-beacon-node.sh nimbus_beacon_node mainnet "$@"

