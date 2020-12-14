# Validating with a Raspberry Pi: Mainnet advice

Whether or not your Pi is up to the task will depend on a number of factors such as SSD speed, network connectivity, etc. As such, it's best to verify performance  on a testnet first.

The best thing you can do is to set your Pi to run Pyrmont. **If you have no trouble syncing and attesting on Pyrmont, your setup should be more than good enough for mainnet** as well (Mainnet is expected to use fewer resources).

<blockquote class="twitter-tweet" data-conversation="none"><p lang="en" dir="ltr">We&#39;ve been running lots of PIs and NanoPCs 24/7 for 3 years and never got a hardware fail. It is easy (and cheap) to get redundancy of components (even spare PIs in different locations, more of this to come).</p>&mdash; Ethereum on ARM (@EthereumOnARM) <a href="https://twitter.com/EthereumOnARM/status/1332772217420177408?ref_src=twsrc%5Etfw">November 28, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

Although we don't expect a modern Pi to fail, we recommend buying a spare Pi, and enterprise grade SSD, on the off-chance it does; keep your original SD around, to make it easy for you to copy the image over.

Finally in order to make sure your Pi autorestarts on boot, we recommend [setting up a systemd service](https://www.raspberrypi.org/documentation/linux/usage/systemd.md). For the details on how to do this, see [this page](./beacon-node-systemd.md)

