#!/bin/sh
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/Library/Apple/usr/bin:/Library/Scripts/Nimbus:/Library/Scripts/Nimbus:scripts

source /etc/nimbus.config

cd "/Library/Scripts/Nimbus"

/Library/Scripts/Nimbus/nimbus_beacon_node --web3-url="${WEB3_URL}" --network="${NETWORK}"
