# Prepare your machine

Nimbus runs on Linux, macOS, Windows, and Android.

You can install Nimbus either using precompiled binaries or build from source.

## System requirements

Check that your machine matches the [minimal system requirements](./hardware.md). The operating system must be a version supported by its vendor.

## Build prerequisites

!!! tip
    If you are planning to use the precompiled binaries, you can skip straight to the [time section](#time)!

When building from source, you will need additional build dependencies to be installed:

- Developer tools (C compiler, Make, Bash, Git)

<!-- TODO: Please test whether the instructions below are correct. I think we are missing some dependencies on Windows. -->
<!--       Microsoft offer virtual machines that you can use for testing here: -->
<!--       https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/ -->

=== "Linux"

    On common Linux distributions the dependencies can be installed with:

    ```sh
    # Debian and Ubuntu
    sudo apt-get install build-essential git-lfs

    # Fedora
    dnf install @development-tools gcc-g++

    # Arch Linux, using an AUR manager
    yourAURmanager -S base-devel git-lfs
    ```

=== "macOS"

    The Command Line Tools package is available as part of Xcode and can be installed via the Terminal application:

    ```sh
    xcode-select --install
    ```

=== "Windows"

    - Install [Git for Windows](https://gitforwindows.org/) and [NASM](https://www.nasm.us/) to build Nimbus on Windows. In Terminal:

    ```sh
    winget install Git.Git
    winget install NASM.NASM
    ```

    - Run all following commands in a "Git Bash" shell (instead of PowerShell or Terminal) to set up the [llvm-mingw](https://github.com/mstorsjo/llvm-mingw/releases) toolchain:

    ```sh
    cd /c
    curl -LO https://github.com/mstorsjo/llvm-mingw/releases/download/20250709/llvm-mingw-20250709-ucrt-x86_64.zip
    unzip -q llvm-mingw-20250709-ucrt-x86_64.zip && mv llvm-mingw-20250709-ucrt-x86_64 llvm-mingw
    cp llvm-mingw/bin/mingw32-make.exe llvm-mingw/bin/make.exe
    cd ~
    echo 'export PATH="/c/llvm-mingw/bin:/c/Program Files/NASM:$PATH"' >> ~/.bashrc
    source ~/.bashrc
    ```

    - Use a "Git Bash" shell to clone and build `nimbus-eth2`.

=== "Android"

    - Install the [Termux](https://termux.dev/en/) app from FDroid or the Google Play store
    - Install a [PRoot](https://wiki.termux.com/wiki/PRoot) of your choice following the instructions for your preferred distribution.
    Note, the Ubuntu PRoot is known to contain all Nimbus prerequisites compiled on Arm64 architecture (the most common architecture for Android devices).

    Assuming you use Ubuntu PRoot:

    ```sh
    apt install build-essential git-lfs
    ```

## Time

The beacon chain relies on your computer having the correct time set (±0.5 seconds).
It is important that you periodically synchronize the time with an NTP server.

If the above sounds like Latin to you, don't worry.
You should be fine as long as you haven't changed the time and date settings on your computer (they should be set automatically).

=== "Linux"

    On Linux, it is recommended to install [chrony](https://chrony-project.org).

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
