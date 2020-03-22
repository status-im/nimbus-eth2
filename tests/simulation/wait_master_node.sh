#!/bin/bash

if [ ! -f "${MASTER_NODE_PID_FILE}" ]; then
  echo Waiting for master node...
  while [ ! -f "${MASTER_NODE_PID_FILE}" ]; do
    sleep 0.1
  done
fi

