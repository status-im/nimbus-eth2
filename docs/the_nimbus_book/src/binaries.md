# Nimbus binaries

Binary releases can be downloaded from [https://github.com/status-im/nimbus-eth2/releases/latest](https://github.com/status-im/nimbus-eth2/releases/latest).

We currently have binaries available for Linux `AMD64`, `ARM` and `ARM64`, Windows `AMD64` and macOS (`AMD64` and `ARM64`).

## Download

The binaries are available at the bottom of the page under `Assets`. You should see a list that looks like the following:

![](https://i.imgur.com/6wuvM2d.png)

Click on the file that corresponds to your OS and architecture, unpack the archive, read the README and run the binary directly (or through one of our provided wrapper scripts).

## Installation

To install or upgrade a binary release, simply unpack the downloaded archive in a directory of your choice.

After unpacking, you may wish to [verify the checksum](./checksums.md).

## Docker

Nimbus binaries are also published via [Docker](./docker.md).

## Reproducible builds

We've designed the build process to be reproducible. In practice, this means that anyone can verify that these exact binaries were produced from the corresponding source code commits. For more about the philosophy and importance of this feature see [reproducible-builds.org](https://reproducible-builds.org/).

For instructions on how to reproduce those binaries, see "README.md" inside the archive, as well as the [in-depth guide](./distribution_internals.md).
