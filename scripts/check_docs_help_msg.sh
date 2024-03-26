#!/usr/bin/env bash

# Copyright (c) 2023-2024 Status Research & Development GmbH.
# Licensed under either of:
# - Apache License, version 2.0
# - MIT license
# at your option. This file may not be copied, modified, or distributed
# except according to those terms.

set -euo pipefail
DOC_FILE='docs/the_nimbus_book/src/options.md'
DOC_USAGE=$(sed -n '/Usage/,/^...$/ { /^...$/d; p; }' "${DOC_FILE}")
BIN_USAGE=$(
  COLUMNS=200 build/nimbus_beacon_node --help | \
    sed -n '/Usage/,/Available sub-commands/ { /Available sub-commands/d; p; }' | \
    sed 's/\\x1B\\[[0-9;]*[mG]//g' | \
    sed 's/[[:space:]]*$//'
)
if ! diff -u <(echo "${DOC_USAGE}") <(echo "${BIN_USAGE}"); then
  echo "Please update '${DOC_FILE}' to match 'COLUMNS=200 nimbus_beacon_node --help'"
  exit 1
fi
