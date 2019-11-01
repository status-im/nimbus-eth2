#!/bin/bash

# TODO This script will no longer be necessary once we switch
# to the native LibP2P

# Deal with previous execution of the deamon leaving behind
# socket files that prevent the deamon from launching again
# inside the container:
killall p2pd
rm -rf /tmp/*

beacon_node "$@"

