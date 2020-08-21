# Installation

The Nimbus beacon chain can run on Linux, macOS, Windows, and Android. At the moment, Nimbus has to be built from source.

## Time

The beacon chain relies on your computer having the correct time set (plus or minus 0.5 seconds).

We recommended you run a high quality time service on your computer such as:

* GPS
* NTS (network time security, [IETF draft](https://tools.ietf.org/html/draft-ietf-ntp-using-nts-for-ntp-19))
* [Roughtime](https://roughtime.googlesource.com/roughtime) (google)

At a minimum, you should run an NTP client on the server.

If that sounds like latin to you, don't worry. For testnet purposes, you should be fine as long as your computer is set to the correct time.

## External Dependencies

- Developer tools (C compiler, Make, Bash, Git)
- [PCRE](https://www.pcre.org/)

Nimbus will build its own local copy of Nim, so Nim is not an external dependency, 

## Linux

On common Linux distributions the dependencies can be installed with

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
brew install pcre cmake
```

### Windows

You can install the developer tools by following the instruction in our [Windows dev environment section](./advanced.md#windows-dev-environment).
We also provide a downloading script for prebuilt PCRE.

### Android

- Install the [Termux](https://termux.com) app from FDroid or the Google Play store
- Install a [PRoot](https://wiki.termux.com/wiki/PRoot) of your choice following the instructions for your preferred distribution.
  Note, the Ubuntu PRoot is known to contain all Nimbus prerequisites compiled on Arm64 architecture (the most common architecture for Android devices).

Assuming you  use Ubuntu PRoot

```sh
apt install build-essential git libpcre3-dev
```

## Next steps

You're now ready to move on to [running a validator on Medalla](./medalla.md).
