#!/bin/bash

# Kill child processes on Ctrl-C by sending SIGTERM to the whole process group,
# passing the negative PID of this shell instance to the "kill" command.
# Trap and ignore SIGTERM, so we don't kill this process along with its children.
trap '' SIGTERM
trap 'kill -- -$$' SIGINT EXIT

./make_genesis.sh

# multitail support
MULTITAIL="${MULTITAIL:-multitail}" # to allow overriding the program name
USE_MULTITAIL="${USE_MULTITAIL:-no}" # make it an opt-in
type "$MULTITAIL" &>/dev/null || USE_MULTITAIL="no"

# Kill child processes on Ctrl-C by sending SIGTERM to the whole process group,
# passing the negative PID of this shell instance to the "kill" command.
# Trap and ignore SIGTERM, so we don't kill this process along with its children.
if [ "$USE_MULTITAIL" = "no" ]; then
  trap '' SIGTERM
  trap 'kill -- -$$' SIGINT EXIT
fi

if [ "$USE_MULTITAIL" != "no" ]; then
  COMMANDS=()
  # "multitail" closes the corresponding panel when a command exits, so let's make sure it doesn't exit
  COMMANDS+=( " -cT ansi -t 'nimbus' -l './run_nimbus.sh 0; echo [node execution completed]; while true; do sleep 100; done'" )
  COMMANDS+=( " -cT ansi -t 'trinity' -l 'sleep 3; ./run_trinity.sh; echo [node execution completed]; while true; do sleep 100; done'" )
  COMMANDS+=( " -cT ansi -t 'lighthouse' -l 'sleep 3; ./run_lighthouse.sh; echo [node execution completed]; while true; do sleep 100; done'" )
  eval $MULTITAIL -s 3 -M 0 -x \"Multichain\" "${COMMANDS[@]}"
else
  ./run_nimbus.sh 0 &
  sleep 2
  ./run_trinity.sh &
  ./run_lighthouse.sh &
  wait
fi
