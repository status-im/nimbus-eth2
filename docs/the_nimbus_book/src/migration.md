# Migrate from Prysm

> Hat tip to Michael Sproul for his [wonderful guide](https://lighthouse.sigmaprime.io/switch-to-lighthouse.html) on how to migrate from Prysm to Lighthouse.

</br>

**1. Sync the Nimbus beacon node**

Sync a Nimbus beacon node. You can follow the [Nimbus quickstart guide](./quick-start.md).  Syncing the beacon node might take up to 30h depending on your hardware, so you should keep validating using your current setup until it completes.

</br>

**2. Disable the Prysm validator client**

Once your Nimbus beacon node has synced and you're satisfied that it's working, stop and disable the Prysm validator client (you can also stop the Prysm beacon node if you wish).


If you're using systemd and your service is called `prysmvalidator`, run the following commands to stop and disable the service:

```
sudo systemctl stop prysmvalidator.service
sudo systemctl disable prysmvalidator.service
```

It's important that you disable the Prysm validator as well as stopping it, to prevent it from starting up again on reboot.

</br>

**3. Export slashing protection history**

Run the following to export your Prysm validator's [slashing protection](https://eips.ethereum.org/EIPS/eip-3076) history:

```
prysm.sh validator slashing-protection export --datadir=/your/prysm/wallet --slashing-protection-export-dir=/path/to/export_dir
```

To be extra sure that your validator has stopped, wait a few epochs and confirm that your validator have stopped attesting (check [beaconcha.in](https://beaconcha.in/)).

</br>

**4. Import your validator key(s) into Nimbus**

Follow the instructions [outlined here](./keys.md).

> To check that your key(s) has been successfully imported, look in `build/data/shared_mainet_0` under `secrets`.

</br>

**5. Import your slashing protection history**

To import the slashing protection history you exported in **step 3**, from the `nimbus-eth2` directory run:


.
.
.

*TO BE COMPLETED*



