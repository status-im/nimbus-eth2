# Prepare your machine

The Nimbus beacon node runs on Linux, macOS, Windows, and Android.

## System requirements

Check that your machine matches the [minimal system requirements](./hardware.md).

## Time

The beacon chain relies on your computer having the correct time set (±0.5 seconds). It is important that you periodically synchronize the time with an NTP server.

If the above sounds like latin to you, don't worry. You should be fine as long as you haven't messed around with the time and date settings on your computer (they should be set automatically).

### Windows and macOS

Make sure that the options for setting time automatically are enabled.

### Linux

On Linux, it is recommended to install [chrony](https://chrony.tuxfamily.org/).

To install it:

```sh
# Debian and Ubuntu
sudo apt-get install -y chrony

# Fedora
sudo dnf install chrony

# Archlinux, using an AUR manager
yourAURmanager chrony
```

## Execution client

To run a beacon node, you need to have access to an execution client exposing the web3 API - throughout, we'll assume an execution client is running on the same machine as the beacon node, but this is not required.

See the [execution client](./eth1.md) guide for further instructions!
