# Windows-specific requirements

Run the wrapper scripts from a [Git for Windows](https://gitforwindows.org/) Bash shell.

If you run the beacon node binary directly, prefix it with "winpty -- ". It
will increase the chance of Ctrl+C working inside that "mintty" terminal emulator.

