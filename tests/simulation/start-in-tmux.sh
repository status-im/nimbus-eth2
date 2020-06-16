#!/bin/bash

set -eo pipefail

cd "$(dirname "$0")"

TMUX_CMD="${TMUX_CMD:-tmux}"
USE_TMUX="${USE_TMUX:-no}"
type "$TMUX_CMD" &>/dev/null || { echo "${TMUX_CMD}" is missing; USE_TMUX="no"; }

if [[ "$USE_TMUX" != "no" ]]; then
  TMUX_SESSION_NAME="${TMUX_SESSION_NAME:-nbc-sim}"

  export USE_TMUX=yes
  export TMUX_CMD
  export TMUX_SESSION_NAME

  $TMUX_CMD new-session -s "${TMUX_SESSION_NAME}" -d

  # maybe these should be moved to a user config file
  $TMUX_CMD set-option -t "${TMUX_SESSION_NAME}" history-limit 999999
  $TMUX_CMD set-option -t "${TMUX_SESSION_NAME}" remain-on-exit on
  $TMUX_CMD set -t "${TMUX_SESSION_NAME}" mouse on

  # We create a new window, so the above settings can take place
  $TMUX_CMD new-window -d -t "${TMUX_SESSION_NAME}" -n "sim"
  $TMUX_CMD kill-pane -t "${TMUX_SESSION_NAME}:0"

  trap 'tmux kill-session -t "${TMUX_SESSION_NAME}"' SIGINT EXIT

  $TMUX_CMD new-window -t "${TMUX_SESSION_NAME}" -n "start-script" "$PWD/start.sh"
  $TMUX_CMD select-window -t "${TMUX_SESSION_NAME}:start-script"

  #$TMUX_CMD send-keys -t "${TMUX_SESSION_NAME}:0" "$PWD/start.sh" Enter
  #$TMUX_CMD select-window -t "${TMUX_SESSION_NAME}:0"
  # $TMUX_CMD attach-session -t "${TMUX_SESSION_NAME}"

  $TMUX_CMD attach-session -t "${TMUX_SESSION_NAME}"
else
  ./start.sh
fi

