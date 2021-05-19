# Nimbus binaries

We currently have binaries available for Linux `AMD64`, `ARM32` and `ARM64`, Windows and  MacOS (`AMD64` and `ARM64`).

You can find the latest release here: [https://github.com/status-im/nimbus-eth2/releases](https://github.com/status-im/nimbus-eth2/releases)

Scroll to the bottom of the first release you see, and click on `Assets`. You should see a list that looks like the following:

![](https://i.imgur.com/R33o4MG.png)

Click on the `tar.gz` file that corresponds to your OS and architecture, unpack the archive, read the README and run the binary directly (or through one of our provided wrapper scripts).

We've designed the build process to be reproducible. In practice, this means that anyone can verify that these exact binaries were produced from the corresponding source code commits. For more about the philosophy and importance of this feature see [reproducible-builds.org](https://reproducible-builds.org/).

For instructions on how to reproduce the build, [see here](https://github.com/status-im/nimbus-eth2/blob/master/docker/dist/README.md#reproducing-the-build).

