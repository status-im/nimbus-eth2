# Upgrade / downgrade

Make sure you stay on the lookout for any critical updates to Nimbus.
The best way to do so is through the **announcements** channel on our [discord](https://discord.com/invite/XRxWahP).
The release page can be found [here](https://github.com/status-im/nimbus-eth2/releases/).

!!! note
    If your beacon node is already running, you'll need to restart it for the changes to take effect.

To update to the latest version, either download the binary or compile the beacon node release (see below), then restart the service.

!!! tip
    To check which version of Nimbus you're currently running, run `build/nimbus_beacon_node --version`

## Upgrade to the latest version

=== "Manual installation"
    Open the [Nimbus release page](https://github.com/status-im/nimbus-eth2/releases/latest) and download the file that corresponds to your operation system and machine.

    Once downloaded, unpack the binaries in the same folder as your current version, overwriting the existing files.

    ```sh
    wget <insert download link here>
    tar -xzf nimbus-eth2_Linux_arm64v8*.tar.gz --strip-components 1 -C nimbus-eth2
    rm nimbus-eth2_Linux_arm64v8*.tar.gz
    ```

=== "Debian / Ubuntu"

    Update Nimbus via the package manager as usual

    ```sh
    sudo apt-get update && sudo apt-get upgrade
    ```

=== "Build from source"

    Upgrading Nimbus when built from source is similar to the installation process.

    Run:

    ```sh
    # Download the updated source code
    git pull && make update

    # Build the newly downloaded version
    make -j4 nimbus_beacon_node
    ```

    !!! tip
        If you want to minimize downtime, you can build Nimbus while the node is running!

Complete the upgrade by restarting the node!

## Urgency guidelines

Nimbus releases are marked with the following tags:

- `low-urgency`: update at your own convenience, sometime within our normal update cycle of two weeks
- `medium-urgency`: may contain an important stability fix, it is better to update sooner rather than later
- `high-urgency`: update as soon as you can, this is a critical update required for Nimbus to function correctly


## Install a specific version

Occasionally, you may need to either upgrade or downgrade to a specific version of Nimbus.

Nimbus can safely be downgraded to any version targeting the current hard fork of the chain, unless otherwise noted among the release notes.

=== "Manual installation"

    Download the desired version from [Github](https://github.com/status-im/nimbus-eth2/releases/) and replace the binaries, similar to upgrading.

=== "Debian / Ubuntu"

    Use the package manager to install a specific version:

    ```sh
    sudo apt-get install nimbus-beacon-node=23.2.0
    ```

=== "Build from source"

    To pull a specific version of Nimbus (e.g. `v22.9.1`), run:

    ```sh
    # Switch source code to the desired version
    git checkout v22.9.1 && make update

    # Run the build command as usual
    make -j4 nimbus_beacon_node
    ```

    When later you want to go back to the stable release:

    ```sh
    # Switch source code to the stable version
    git checkout stable && make update

    # Run the build command as usual
    make -j4 nimbus_beacon_node
    ```

Now, restart your node.
