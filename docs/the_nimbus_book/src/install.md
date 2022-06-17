# Prepare your machine

The Nimbus beacon node runs on Linux, macOS, Windows, and Android.

## System requirements

Check that your machine matches the [minimal system requirements](./hardware.md).

## Time

The beacon chain relies on your computer having the correct time set (plus or minus 0.5 seconds). It is important that you periodically synchronize the time with an NTP server.

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
dnf install chrony

# Archlinux, using an AUR manager
yourAURmanager chrony
```

Once installed, the default configuration works well.

At a minimum, you should run an NTP client (such as chrony) on the server.  Note that most operating systems (including macOS') automatically sync with NTP by default.

## Building from source

> 🛈 If you are planning to use the precompiled binaries, you can skip this section and go straight to the [binaries](./binaries.md)!

When building from source, you will need additional build dependencies to be installed:

- Developer tools (C compiler, Make, Bash, Git)

Nimbus will build Nim as part of its build process - you do not need to have the Nim compiler installed.

### Linux

On common Linux distributions the dependencies can be installed with

```sh
# Debian and Ubuntu
sudo apt-get install build-essential git

# Fedora
dnf install @development-tools

# Archlinux, using an AUR manager
yourAURmanager -S base-devel
```

### macOS

Assuming you use [Homebrew](https://brew.sh/) to manage packages

```sh
brew install cmake
```

### Windows

To build Nimbus on windows, the Mingw-w64 build environment is recommended.

Install Mingw-w64 for your architecture using the "[MinGW-W64 Online Installer](https://sourceforge.net/projects/mingw-w64/files/)":

1. Select your architecture in the setup menu (`i686` on 32-bit, `x86_64` on 64-bit)
2. Set threads to `win32`
3. Set exceptions to "dwarf" on 32-bit and "seh" on 64-bit.
4. Change the installation directory to `C:\mingw-w64` and add it to your system PATH in `"My Computer"/"This PC" -> Properties -> Advanced system settings -> Environment Variables -> Path -> Edit -> New -> C:\mingw-w64\mingw64\bin` (`C:\mingw-w64\mingw32\bin` on 32-bit)

Install [Git for Windows](https://gitforwindows.org/) and use a "Git Bash" shell to clone and build `nimbus-eth2`.

> **Note:** If the online installer isn't working you can try installing `Mingw-w64` through [MSYS2](https://www.msys2.org/).

### Android

- Install the [Termux](https://termux.com) app from FDroid or the Google Play store
- Install a [PRoot](https://wiki.termux.com/wiki/PRoot) of your choice following the instructions for your preferred distribution.
  Note, the Ubuntu PRoot is known to contain all Nimbus prerequisites compiled on Arm64 architecture (the most common architecture for Android devices).

Assuming you  use Ubuntu PRoot

```sh
apt install build-essential git
```
