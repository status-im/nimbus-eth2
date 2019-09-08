#!/bin/bash

if test -n "$BASH" ; then script=$BASH_SOURCE
elif test -n "$TMOUT"; then script=${.sh.file}
elif test -n "$ZSH_NAME" ; then script=${(%):-%x}
elif test ${0##*/} = dash; then x=$(lsof -p $$ -Fn0 | tail -1); script=${x#n}
else script=$0
fi

# https://unix.stackexchange.com/a/76518
export REL_PATH=`dirname "$script"`
export ABS_PATH=`exec 2>/dev/null;(cd -- "$REL_PATH") && cd -- "$REL_PATH"|| cd "$REL_PATH"; unset PWD; /usr/bin/pwd || /bin/pwd || pwd`

source ${ABS_PATH}/vendor/nimbus-build-system/scripts/env.sh

