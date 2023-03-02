# Binaries

Binary releases are available from [GitHub](https://github.com/status-im/nimbus-eth2/releases/latest) and our [APT repository](https://apt.status.im/) (Debian/Ubuntu).

We currently have binaries available for Linux `AMD64`, `ARM` and `ARM64`, Windows `AMD64` and macOS (`AMD64` and `ARM64`).

=== "Manual installation"

    The latest release is always available from [Github](https://github.com/status-im/nimbus-eth2/releases/latest) under the **Assets** header at the bottom of the page.

    To install or upgrade a binary release, simply unpack the archive appropriate for your operating system and architecture in a directory of your choice, and run the binary.

    ```sh
    # Create a directory that can hold the beacon chain data and applications - this should be a fast SSD
    mkdir -p nimbus-eth2
    # Unpack the archive into the `nimbus-eth2` directory you just created
    tar xvf nimbus-eth2_Linux_amd64_22.6.1_2444e994.tar.gz --strip-components 1 -C nimbus-eth2
    ```

    After unpacking, you may wish to [verify the checksum](./checksums.md).

=== "Debain / Ubuntu"

    Install Nimbus from our [APT repository](https://apt.status.im/):

    ```sh
    # Add the nimbus repository
    echo 'deb https://apt.status.im/nimbus all main' | sudo tee /etc/apt/sources.list.d/nimbus.list
    # Import the GPG key
    sudo curl https://apt.status.im/pubkey.asc -o /etc/apt/trusted.gpg.d/apt-status-im.asc

    # Update repository files and install Nimbus components
    sudo apt-get update
    sudo apt-get install nimbus-beacon-node nimbus-validator-client
    ```

    !!! note "Helper scripts"
        When installing via package manager, replace `run-mainnet-beacon-node.sh` and similar helper scripts used in this guide with `nimbus_beacon_node` - blockchain data will be written to the default [data directory](./data-dir.md) unless changed with `--data-dir`.

    !!! tip "`systemd`"
        Packages include `systemd` service unit files - see the [systemd guide](./beacon-node-systemd.md) for usage instructions - the `nimbus` user is created as part of the installation process!

## Reproducible builds

We've designed the build process to be reproducible. In practice, this means that anyone can verify that these exact binaries were produced from the corresponding source code commits. For more about the philosophy and importance of this feature see [reproducible-builds.org](https://reproducible-builds.org/).

For instructions on how to reproduce those binaries, see "README.md" inside the archive, as well as the [in-depth guide](./distribution_internals.md).
