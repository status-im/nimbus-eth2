# Nimbus binaries

Nimbus binaries exist for Nimbus -- initially `x86 64-bit`, but Windows, MacOS and additional Linux binaries will be added shortly.

You can find the latest release here: [https://github.com/status-im/nimbus-eth2/releases](https://github.com/status-im/nimbus-eth2/releases)

Scroll to the bottom of the first release you see, and click on `Assets`. You should see a list that looks like the following:

![](https://i.imgur.com/4FBhUpk.png)

Click on the first option, the `tar.gz` file, and follow the instructions [here](https://github.com/status-im/nimbus-eth2/blob/master/docker/dist/README.md).

We've designed this binary to be reproducible: in practice, this means that anyone who wishes to can verify that no vulnerabilities or backdoors have been introduced during the compilation process. For more on the philosophy and importance of reproducible builds [see here](https://reproducible-builds.org/).

For instructions on how to reproduce the build, [see here](https://github.com/status-im/nimbus-eth2/blob/master/docker/dist/README.md#reproducing-the-build).

