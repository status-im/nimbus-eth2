# Migrate from another client

This guide will take you through the basics of how to migrate to Nimbus from another client.
See [here](./migration-options.md) for advanced options.

**Please take your time to get this right.**
Don't hesitate to reach out to us in the `#helpdesk` channel of [our discord](https://discord.gg/j3nYBUeEad) if you come across a stumbling block.
We are more than happy to help guide you through the migration process.
Given what's at stake, there is no such thing as a stupid question.

!!! info ""
    Unlike other clients, Nimbus does not require a separate validator client.
    Instead, validators run in the beacon node process.

!!! warning
    **The most important takeaway is that you ensure that two clients will never validate with the same keys at the same time.**
    In other words, you must ensure that your original client is stopped, and no longer validating, before importing your keys into Nimbus.

## Steps

### 1. Sync the Nimbus beacon node

No matter which client you are migrating over from, the first step is to sync the Nimbus beacon node.

The easiest and fastest way to do this is to follow the [beacon node quick start guide](./quick-start.md) and perform a [trusted node sync](./trusted-node-sync.md) from the source client.

Once your Nimbus beacon node has synced and you're satisfied that it's working, move to **Step 2**.

!!! tip
    You can keep track of your [syncing progress](keep-an-eye.md#keep-track-of-your-syncing-progress) with the following command:

    ```
    curl -X GET http://localhost:5052/eth/v1/node/syncing
    ```
    Look for an `"is_syncing":false` in the response to confirm that your node has synced.

### 2. Stop your existing client and export your slashing protection history

As part of the migration process, you need to stop your existing client and export its [slashing protection database](https://eips.ethereum.org/EIPS/eip-3076).

=== "Prysm"

    #### 1. Disable the Prysm validator client

    Stop and disable the Prysm validator client (you can also stop the Prysm beacon node if you wish).

    If you're using systemd and your service is called `prysmvalidator`, run the following commands to stop and disable the service:

    ```sh
    sudo systemctl stop prysmvalidator.service
    sudo systemctl disable prysmvalidator.service
    ```

    It is important that you disable the Prysm validator as well as stopping it, to prevent it from starting up again on reboot.

    #### 2. Export slashing protection history

    Run the following to export your Prysm validator's [slashing protection](https://eips.ethereum.org/EIPS/eip-3076) history:

    ```sh
    prysm.sh validator slashing-protection-history export \
    --datadir=/your/prysm/wallet \
    --slashing-protection-export-dir=/path/to/export_dir
    ```

    You will then find the `slashing-protection.json` file in your specified `/path/to/export_dir` folder.

=== "Lighthouse"

    #### 1. Disable the Lighthouse validator client

    The validator client needs to be stopped in order to export, to guarantee that the data exported is up to date.

    If you're using systemd and your service is called `lighthousevalidator`, run the following command to stop and disable the service:

    ```sh
    sudo systemctl stop lighthousevalidator
    sudo systemctl disable lighthousevalidator
    ```

    You may also wish to stop the beacon node:

    ```sh
    sudo systemctl stop lighthousebeacon
    sudo systemctl disable lighthousebeacon
    ```

    It is important that you disable the service as well as stopping it, to prevent it from starting up again on reboot.

    #### 2. Export slashing protection history

    You can export Lighthouse's database with this command:

    ```sh
    lighthouse account validator slashing-protection export slashing-protection.json
    ```

    This will export your history in the correct format to `slashing-protection.json`.

=== "Teku"

    #### 1. Disable Teku

    If you're using systemd and your service is called `teku`, run the following command to stop and disable the service:

    ```sh
    sudo systemctl stop teku
    sudo systemctl disable teku
    ```

    It is important that you disable the service as well as stopping it, to prevent it from starting up again on reboot.


    #### 2. Export slashing protection history

    You can export Teku's database with this command:

    ```sh
    teku slashing-protection export --data-path=/home/me/me_node --to=/home/slash/slashing-protection.json
    ```

    Where:

    - `--data-path` specifies the location of the Teku data directory.
    - `--to` specifies the file to export the slashing-protection data to (in this case `/home/slash/slashing-protection.json`).

=== "Nimbus"

    #### 1. Disable the Nimbus validator client

    Once your Nimbus beacon node on your new setup has synced and you're satisfied that it's working, stop and disable the Nimbus validator client on your current setup.

    If you're using systemd and your service is called `nimbus-eth2-mainnet`, run the following commands to stop and disable the service:

    ```
    sudo systemctl stop nimbus-eth2-mainnet.service
    sudo systemctl disable nimbus-eth2-mainnet.service
    ```

    It is important that you disable the service as well as stopping it, to prevent it from starting up again on reboot.

    #### 2. Export slashing protection history

    Run the following to export your Nimbus validator's [slashing protection](https://eips.ethereum.org/EIPS/eip-3076) history:

    ```
    build/nimbus_beacon_node slashingdb export slashing-protection.json
    ```

    This will export your history in the correct format to `slashing-protection.json`.

!!! tip
    To be extra sure that your validator has stopped, wait a few epochs and confirm that your validator has stopped attesting (check its recent history on [beaconcha.in](https://beaconcha.in/)).
    Only after that, continue with the next step of this guide.


### 3. Import your validator key(s) into Nimbus

To import your validator key(s), follow the instructions [in our validator guide](./run-a-validator.md#2-import-your-validator-keys).

!!! tip
    To check that your key(s) has been successfully imported, look for a file named after your public key in `build/data/shared_mainet_0/secrets/`.

    If you run into an error at this stage, it's probably because the wrong permissions have been set on either a folder or file.
    See [here](faq.md#folder-permissions) for how to fix this.


### 4. Import your slashing protection history

To import the slashing protection history you exported in **step 2**, from the `nimbus-eth2` directory run:

```sh
build/nimbus_beacon_node slashingdb import path/to/export_dir/slashing-protection.json
```

Replacing `/path/to/export_dir` with the file/directory you specified when you exported your slashing protection history.

!!! tip
    Additional slashing protection information can be safely added to slashing protection databases.

### 5. Start the Nimbus validator

Follow the instructions [in our validator guide](./run-a-validator.md#3-start-validating) to start your validator using our pre-built [binaries](./binaries.md).

If you prefer to use Docker, see [our Docker guide](./docker.md).

For a quick guide on how to set up a systemd service, see [our systemd guide](./beacon-node-systemd.md).

## Final thoughts

If you are unsure of the safety of a step, please get in touch with us directly on [discord](https://discord.gg/nnNEBvHu3m).
Additionally, we recommend testing the migration works correctly on a testnet before going ahead on mainnet.

