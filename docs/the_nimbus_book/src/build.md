# Build from source

Building Nimbus from source ensures that all hardware-specific optimizations are turned on.
The build process itself is simple and fully automated, but may take a few minutes.

!!! note "Nim"
    Nimbus is written in the [Nim](https://nim-lang.org) programming language.
    The correct version will automatically be downloaded as part of the build process!

## Prerequisites

!!! tip
    If you are planning to use the precompiled binaries, you can skip this section and go straight to the [binaries](./binaries.md)!

When building from source, you will need additional build dependencies to be installed:

- Developer tools (C compiler, Make, Bash, Git)
- [CMake](https://cmake.org/)

<!-- TODO: Please test whether the instructions below are correct. I think we are missing some dependencies on Windows. -->
<!--       Microsoft offer virtual machines that you can use for testing here: -->
<!--       https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/ -->

=== "Linux"

    On common Linux distributions the dependencies can be installed with

    ```sh
    # Debian and Ubuntu
    sudo apt-get install build-essential git cmake

    # Fedora
    dnf install @development-tools cmake

    # Archlinux, using an AUR manager
    yourAURmanager -S base-devel cmake
    ```

=== "macOS"

    With [Homebrew](https://brew.sh/):

    ```sh
    brew install cmake
    ```

=== "Windows"

    To build Nimbus on Windows, the MinGW-w64 build environment is recommended.

    Install Mingw-w64 for your architecture using the "[MinGW-W64 Online Installer](https://sourceforge.net/projects/mingw-w64/files/)":

    1. Select your architecture in the setup menu (`i686` on 32-bit, `x86_64` on 64-bit).
    2. Set threads to `win32`.
    3. Set exceptions to "dwarf" on 32-bit and "seh" on 64-bit.
    4. Change the installation directory to `C:\mingw-w64` and add it to your system PATH in `"My Computer"/"This PC" -> Properties -> Advanced system settings -> Environment Variables -> Path -> Edit -> New -> C:\mingw-w64\mingw64\bin` (`C:\mingw-w64\mingw32\bin` on 32-bit).

    !!! note
        If the online installer isn't working you can try installing `mingw-w64` through [MSYS2](https://www.msys2.org/).

    Install [Git for Windows](https://gitforwindows.org/) and use a "Git Bash" shell to clone and build `nimbus-eth2`.

=== "Android"

    - Install the [Termux](https://termux.com) app from FDroid or the Google Play store
    - Install a [PRoot](https://wiki.termux.com/wiki/PRoot) of your choice following the instructions for your preferred distribution.
    Note, the Ubuntu PRoot is known to contain all Nimbus prerequisites compiled on Arm64 architecture (the most common architecture for Android devices).

    Assuming you use Ubuntu PRoot

    ```sh
    apt install build-essential git
    ```

## Building the node

### 1. Clone the `nimbus-eth2` repository

```sh
git clone https://github.com/status-im/nimbus-eth2
cd nimbus-eth2
```

### 2. Run the beacon node build process

To build the Nimbus beacon node and its dependencies, run:

```sh
make -j4 nimbus_beacon_node
```

!!! tip
    Omit `-j4` on systems with 4GB of memory or less.
