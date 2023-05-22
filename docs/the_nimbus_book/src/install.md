# Prepare your machine

The Nimbus beacon node runs on Linux, macOS, Windows, and Android.

## System requirements

Check that your machine matches the [minimal system requirements](./hardware.md).

## Build prerequisites

You will need to install developer tools (C compiler, Make, Bash, Git) and [CMake](https://cmake.org/).
See the [build guide](./build.md).

## Time

The beacon chain relies on your computer having the correct time set (±0.5 seconds).
It is important that you periodically synchronize the time with an NTP server.

If the above sounds like Latin to you, don't worry.
You should be fine as long as you haven't changed the time and date settings on your computer (they should be set automatically).

=== "Linux"

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

=== "Windows, macOS"

    Make sure that the options for setting time automatically are enabled.
