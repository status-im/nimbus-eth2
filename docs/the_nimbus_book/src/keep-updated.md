# Keep Nimbus updated

Make sure you stay on the lookout for any critical updates to Nimbus. This best way to do so is through the **announcements** channel on our [discord](https://discord.com/invite/XRxWahP).

> **Note:** If your beacon node is already running, you'll need to disconnect and reconnect for the changes to take effect.

To update to the latest version, either:

## Download the binary

Open the [Nimbus eth2 releases page](https://github.com/status-im/nimbus-eth2/releases/latest) and copy the link for the file that works on your system.

```
wget <insert download link here>
tar -xzf nimbus-eth2_Linux_arm64v8*.tar.gz -C nimbus-eth2
rm nimbus-eth2_Linux_arm64v8*.tar.gz
```

## Compile the beacon node release

> ⚠️   In order to minimise downtime, we recommend updating and rebuilding the beacon node before restarting.

```
git pull && make update
```

Followed by:

```
make nimbus_beacon_node
```

to [rebuild the beacon node](./build.md).


