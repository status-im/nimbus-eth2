#!/bin/sh

NIMBUS_SERVER="$(cat /tmp/nimbus.server.config)"
NIMBUS_ETH="$(cat /tmp/nimbus.eth.config)"
NIMBUS_LAUNCH="$(cat /tmp/nimbus.launch.config)"

echo "NETWORK=\"$NIMBUS_SERVER\"" > /etc/nimbus.config
echo "WEB3_URL=\"$NIMBUS_ETH\"" >> /etc/nimbus.config
echo "DATA_DIR=/var/lib/nimbus" >> /etc/nimbus.config
mkdir "/var/lib/nimbus"

sudo dscl . -create /Users/nimbus
sudo dscl . -create /Users/nimbus UserShell /bin/bash
sudo dscl . -create /Users/nimbus RealName "Nimbus"

sudo dscl . -create /Users/nimbus UniqueID "1012"
sudo dscl . -create /Users/nimbus PrimaryGroupID 80
sudo dscl . -append /Groups/admin GroupMembership nimbus

sudo chown nimbus /var/lib/nimbus

sudo -u nimbus chmod u+rw,g,rw,o=r /var/lib/nimbus

launchctl load /Library/LaunchDaemons/nimbus.plist

if [ NIMBUS_LAUNCH == 1 ]; then
	sudo launchctl start Nimbus
fi

exit 0
