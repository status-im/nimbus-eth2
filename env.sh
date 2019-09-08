#!/bin/bash

# https://unix.stackexchange.com/a/76518
export REL_PATH=`dirname "$0"`
export ABS_PATH=`exec 2>/dev/null;(cd -- "$REL_PATH") && cd -- "$REL_PATH"|| cd "$REL_PATH"; unset PWD; /usr/bin/pwd || /bin/pwd || pwd`

source ${ABS_PATH}/vendor/nimbus-build-system/scripts/env.sh

