# Upgrade / downgrade Nimbus

Make sure you stay on the lookout for any critical updates to Nimbus. This best way to do so is through the **announcements** channel on our [discord](https://discord.com/invite/XRxWahP). The release page can be found [here](https://github.com/status-im/nimbus-eth2/releases/).

> **Note:** If your beacon node is already running, you'll need to disconnect and reconnect for the changes to take effect.

To update to the latest version, either download the binary or compile the beacon node release (see below).

> **Tip:** To check which version of Nimbus you're currently running, run `build/nimbus_beacon_node --version`

## Download the binary

Open the latest [Nimbus release](https://github.com/status-im/nimbus-eth2/releases/latest) and copy the link for the file that works on your system.

```
wget <insert download link here>
tar -xzf nimbus-eth2_Linux_arm64v8*.tar.gz -C nimbus-eth2
rm nimbus-eth2_Linux_arm64v8*.tar.gz
```

## Compile the beacon node release

Run: 

```
git pull && make update
```

Followed by:

```
make nimbus_beacon_node
```

Now, restart your node.

> **Tip:** In order to minimise downtime, we recommend updating and [rebuilding](./build.md) the beacon node **before restarting**.


## Urgency guidelines
As of `v1.4.0`, releases are marked with the following tags:

`low-urgency`: update at your own convenience, sometime within our normal update cycle of two weeks

`medium-urgency`: may contain an important stability fix, it is better to update sooner rather than later

`high-urgency`: update as soon as you can, this is a critical update required for Nimbus to function correctly


## Install a specific version

*Occassionally you may need to either upgrade or downgrade to a specific version of Nimbus.*

To pull a specific version of Nimbus (e.g. `v1.3.0`), run:
```
git checkout v1.3.0 && make update
```

Followed by:

```
make nimbus_beacon_node
```

Now, restart your node.

> **Note:** Alternatively, you can grab the appropriate binary release - create a backup of your `build` folder, then download the appropriate binary from here: [https://github.com/status-im/nimbus-eth2/releases/tag/v1.3.0](https://github.com/status-im/nimbus-eth2/releases/tag/v1.3.0)

### Go back to stable
If you need to go back to the latest (stable) version, run:
```
git checkout stable &&  make update
```

Followed by

```
make nimbus_beacon_node
```

Don't forget to restart your node.

