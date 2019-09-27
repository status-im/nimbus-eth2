
#!/bin/bash

# Deal with previous execution of the deamon leaving behind
# socket files that prevent the deamon from launching again
# inside the container.
killall p2pd
rm -rf /tmp/*

if [[ "$2" == "" ]]; then
  # TODO This is a normal execution of a long-running testnet node.
  # If the nat is enabled at the moment, the node fails to start.
  beacon_node --nat:none
else
  # This is a one-off command such as createTestnet.
  # We cannot reuse the command above, because the --nat option
  # is not compatible with most of the commands.
  beacon_node "$@"
fi
