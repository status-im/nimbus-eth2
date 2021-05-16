# Migrate from another client

## Step 1 - Sync the Nimbus beacon node
No matter which client you are migrating over from, the first step is to sync the beacon node.

The easiest way to do this is to follow the [Nimbus quickstart guide](./quick-start.md).  Syncing the beacon node might take up to 30h depending on your hardware, so you should keep validating using your current setup until it completes.


## Step 2 - Export your slashing protection history
> Hat tip to Michael Sproul for his [wonderful guide](https://lighthouse.sigmaprime.io/switch-to-lighthouse.html) on how to migrate from Prysm to Lighthouse.


### Export from Prysm

**1. Disable the Prysm validator client**

Once your Nimbus beacon node has synced and you're satisfied that it's working, stop and disable the Prysm validator client (you can also stop the Prysm beacon node if you wish).


If you're using systemd and your service is called `prysmvalidator`, run the following commands to stop and disable the service:

```
sudo systemctl stop prysmvalidator.service
sudo systemctl disable prysmvalidator.service
```

It's important that you disable the Prysm validator as well as stopping it, to prevent it from starting up again on reboot.

</br>

**2. Export slashing protection history**

Run the following to export your Prysm validator's [slashing protection](https://eips.ethereum.org/EIPS/eip-3076) history:

```
prysm.sh validator slashing-protection export --datadir=/your/prysm/wallet --slashing-protection-export-dir=/path/to/export_dir
```

To be extra sure that your validator has stopped, wait a few epochs and confirm that your validator have stopped attesting (check [beaconcha.in](https://beaconcha.in/)).

</br>

### Export from Lighthouse
*coming soon*

### Export from Teku
*coming soon*


## Step 3 - Import your validator key(s) into Nimbus
To import you validator key(s), follow the instructions [outlined here](./keys.md).

> To check that your key(s) has been successfully imported, look for a file named after your public key in `build/data/shared_mainet_0/secrets/`.

## Step 4 - Import your slashing protection history

To import the slashing protection history you exported in **step 3**, from the `nimbus-eth2` directory run:

```
build/nimbus_beacon_node slashingdb import --interchange=path/to/export_dir/interchange.json
```

Replacing `/path/to/export_dir` with the directory you specified when you exported your slashing protection history


## Step 5 - Start the Nimbus validator

Follow the instructions [here](./connect-eth2.html) to start your validator using our pre-built [binaries](./binaries.md).

If you prefer to use Docker, see [here](./docker.md)

For a quick guide on how to set up a systemd service, see [here](./beacon-node-systemd.md)


## Final thoughts

If you are unsure of the safety of a step, please get in touch with us directly on [discord](https://discord.gg/nnNEBvHu3m). Additionally, we recommend testing the migration works correctly on a testnet before going ahead on mainnet.




