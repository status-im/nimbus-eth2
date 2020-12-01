# Keep Nimbus updated

Make sure you stay on the lookout for any critical updates to Nimbus. This best way to do so is through the **announcements** channel on our [discord](https://discord.com/invite/XRxWahP).

To update to the latest version, run:

```
git pull && make update
```

Followed by:

```
make nimbus_beacon_node
```

to [rebuild the beacon node](./build.md).

> ⚠️   In order to minimise downtime, we recommend updating and rebuilding the beacon node before restarting.

> **Note:** If your beacon node is already running, you'll need to disconnect and reconnect for the changes to take effect.


