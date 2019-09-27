#!/bin/bash

./make_genesis.sh

# multitail support
MULTITAIL="${MULTITAIL:-multitail}" # to allow overriding the program name
USE_MULTITAIL="${USE_MULTITAIL:-no}" # make it an opt-in
type "$MULTITAIL" &>/dev/null || USE_MULTITAIL="no"

if [ "$USE_MULTITAIL" != "no" ]; then
  COMMANDS=()
  # "multitail" closes the corresponding panel when a command exits, so let's make sure it doesn't exit
  COMMANDS+=( " -cT ansi -t 'nimbus' -l './run_nimbus.sh 10 5; echo [node execution completed]; while true; do sleep 100; done'" )
  COMMANDS+=( " -cT ansi -t 'trinity' -l 'sleep 3; ./run_trinity.sh 0 5; echo [node execution completed]; while true; do sleep 100; done'" )
  COMMANDS+=( " -cT ansi -t 'lighthouse' -l 'sleep 3; ./run_lighthouse.sh 5 5; echo [node execution completed]; while true; do sleep 100; done'" )
  COMMANDS+=( " -cT ansi -t 'prysm' -l 'sleep 3; ./run_prysm.sh 15 5; echo [node execution completed]; while true; do sleep 100; done'" )
  COMMANDS+=( " -cT ansi -t 'lodestar' -l 'sleep 3; ./run_lodestar.sh 20 5; echo [node execution completed]; while true; do sleep 100; done'" )
  eval $MULTITAIL -s 3 -M 0 -x \"Multichain\" "${COMMANDS[@]}"
else
  trap 'kill -9 -- -$$' SIGINT EXIT SIGTERM

  ./run_nimbus.sh &
  sleep 2
  ./run_trinity.sh &
  ./run_lighthouse.sh &
  ./run_prysm.sh &
  ./run_lodestar.sh &
  wait
fi
