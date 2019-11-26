#!/bin/bash

# Read in variables
set -a
# shellcheck source=/dev/null
source "$(dirname "$0")/vars.sh"

cd $(dirname "$0")
rm -rf data

tmux new-session -s 'beacon_node' -d

# maybe these should be moved to a user config file
tmux set-option -g history-limit 999999
tmux set -g mouse on

tmux send-keys -t 0 './start.sh' Enter
tmux new-window -n "demo_node" "./wait_master_node.sh && ./run_node.sh 0"

tmux attach-session -d

