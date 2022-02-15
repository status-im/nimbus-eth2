# Install dependencies

The Nimbus beacon chain can run on Linux, macOS, Windows, and Android. At the moment, Nimbus has to be built from source, which means you'll need to install some dependencies.

## Time

The beacon chain relies on your computer having the correct time set (plus or minus 0.5 seconds).

We recommended you run a high quality time service on your computer such as [chrony](https://chrony.tuxfamily.org/).
Chrony is much more performant than the default NTP server.
It's a simple install: 

```sh
# Debian and Ubuntu
sudo apt-get install -y chrony

# Fedora
dnf install chrony

# Archlinux, using an AUR manager
yourAURmanager chrony
```

It's available on most package managers.

Once installed, the default configuration is enough.

At a minimum, you should run an NTP client (such as chrony) on the server.

> **Note:** Most operating systems (including macOS) automatically sync with NTP by default, however it's still recommended to run chrony.

## External Dependencies

- Developer tools (C compiler, Make, Bash, Git)

Nimbus will build its own local copy of Nim, so Nim is not an external dependency,

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

> **Note:** If the online installer isn't working you can try installing`Mingw-w64` through [MSYS2](https://www.msys2.org/).

### Android

- Install the [Termux](https://termux.com) app from FDroid or the Google Play store
- Install a [PRoot](https://wiki.termux.com/wiki/PRoot) of your choice following the instructions for your preferred distribution.
  Note, the Ubuntu PRoot is known to contain all Nimbus prerequisites compiled on Arm64 architecture (the most common architecture for Android devices).

Assuming you  use Ubuntu PRoot

```sh
apt install build-essential git
```
