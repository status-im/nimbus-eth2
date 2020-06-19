# Installation

Beacon chain can run on Linux, macOS, Windows, and Android. At the moment, Nimbus has to be built from source.

## External Dependencies

- Developer tools (C compiler, Make, Bash, Git)
- PCRE

Nim is not an external dependency, Nimbus will build its own local copy.

## Linux

On common Linux distributions the dependencies can be installed with:

```sh
# Debian and Ubuntu
sudo apt-get install build-essential git libpcre3-dev

# Fedora
dnf install @development-tools pcre

# Archlinux, using an AUR manager for pcre-static
yourAURmanager -S base-devel pcre-static
```

### macOS

Assuming you use [Homebrew](https://brew.sh/) to manage packages

```sh
brew install pcre
```

### Windows

You can install the developer tools by following the instruction in our [Windows dev environment section](./advanced.md#windows-dev-environment).
It also provides a downloading script for prebuilt PCRE.

### Android

- Install the [Termux](https://termux.com) app from FDroid or the Google Play store
- Install a [PRoot](https://wiki.termux.com/wiki/PRoot) of your choice following the instructions for your preferred distribution.
  Note, the Ubuntu PRoot is known to contain all Nimbus prerequisites compiled on Arm64 architecture (common architecture for Android devices).

_Assuming Ubuntu PRoot is used_

```sh
apt install build-essential git libpcre3-dev
```
