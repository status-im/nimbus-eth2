# Nimbus binaries

We currently have binaries available for Linux `AMD64`, `ARM` and `ARM64`, Windows `AMD64` and macOS (`AMD64` and `ARM64`).

You can find the latest release here: [https://github.com/status-im/nimbus-eth2/releases](https://github.com/status-im/nimbus-eth2/releases)

Scroll to the bottom of the first (non-nightly) release you see, and click on `Assets`. You should see a list that looks like the following:

![](https://i.imgur.com/6wuvM2d.png)

Click on the `tar.gz` file that corresponds to your OS and architecture, unpack the archive, read the README and run the binary directly (or through one of our provided wrapper scripts).

We've designed the build process to be reproducible. In practice, this means that anyone can verify that these exact binaries were produced from the corresponding source code commits. For more about the philosophy and importance of this feature see [reproducible-builds.org](https://reproducible-builds.org/).

For instructions on how to reproduce those binaries, see "README.md" inside the archive.
