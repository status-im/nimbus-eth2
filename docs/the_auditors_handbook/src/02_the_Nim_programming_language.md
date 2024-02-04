# The Nim Programming Language

!!! warning
    This auditors' handbook is frozen and obsolete; the [Nim language manual](https://nim-lang.org/docs/manual.html) alongside [other Nim documentation](https://nim-lang.org/documentation.html), [Status Nim style guide](https://status-im.github.io/nim-style-guide/), [Chronos guides](https://github.com/status-im/nim-chronos/blob/master/docs/src/SUMMARY.md), and [Nim by Example](https://nim-by-example.github.io/getting_started/) supercede it.

The Nim programming language is a compiled language, with strong static typing.

The rest of the Handbook will assume that Nim-by-example was read.

Nim compilation process is in 2 phases, first lowering the Nim code to C, C++ or Javascript. Then for machine code, rely on the C/C++ compiler to produce the final code.

Nim can target any combination of C compiler, host OS and hardware architecture as long as the C compiler supports it.

## Installing

Nim can be installed via:
- A Linux distribution package manager or Homebrew on MacOS
- Instructions at [https://nim-lang.org/install.html](https://nim-lang.org/install.html)
- Docker: [https://hub.docker.com/r/nimlang/nim/](https://hub.docker.com/r/nimlang/nim/)
- Choosenim [https://github.com/dom96/choosenim](https://github.com/dom96/choosenim)

Nim Vagrant [https://github.com/status-im/nim-vagrant](https://github.com/status-im/nim-vagrant) is unmaintained but might
help setting up your own virtualized environment.

We target Nim 1.2.2 and should be compatible with the latest stable, Nim 1.2.4

## Casings

Nim has unusual partial case insensitivity for identifiers. The rationales being:
- Preventing bugs when using `SDL_QUIT` instead of `SDL_Quit`.
- Having consistent casing in a codebase even when relying on external dependencies with different casing.

The convention used in Nim-Beacon-Chain is:
- `snake_case` for fields and procedures names from the Ethereum spec
- `MACRO_CASE` for Ethereum spec constants
- `PascalCase` for all types (Ethereum or additional)
- `camelCase` for our own additional code
- `PascalCase` for our additional constants

In summary, we respect the Ethereum spec for Ethereum specified identifiers
and use Nim NEP-1 for the rest.

## Checking the C code

By default the intermediate C code produced by the Nim compiler is available at

- `$HOME/.nim/compiled_project_d` on UNIX systems
- `$HOME/nimcache/compiled_project_d` on Windows

The suffix `_d` indicates a debug build, the suffix `_d` indicates a release build

## Compiler options

At the time of writing, NBC targets Nim v1.2.2 compiler.
The build system is at [https://github.com/status-im/nimbus-build-system](https://github.com/status-im/nimbus-build-system)
No patching is done at the moment on the Nim compiler, we use vanilla v1.2.2 upstream.

Nim compiler offers debug, release with `-d:release` and danger with `-d:danger` flag.

The debug and `-d:release` build differ by, the verbosity of stacktraces and passing `-O3` or equivalent to the C compiler.

Runtime checks (overflow, array bounds checks, nil checks, ...) are still included in `-d:release` build. We also choose to have verbose stacktraces in NBC.

A danger build optimizes away all runtime checks and debugging help like stackframes. This might have a significant impact on performance
as it may enable optimizations that were not possible like optimizing tail calls. This is not used in NBC.

## References

- Nim by example:
  - [https://nim-by-example.github.io/getting_started/](https://nim-by-example.github.io/getting_started/)

- The Nim Manual, is a specification of how Nim should behave\
  [https://nim-lang.org/docs/manual.html](https://nim-lang.org/docs/manual.html)

- Nim tutorials
  - [https://nim-lang.org/docs/tut1.html](https://nim-lang.org/docs/tut1.html)
  - [https://nim-lang.org/docs/tut2.html](https://nim-lang.org/docs/tut2.html)
  - [https://nim-lang.org/docs/tut3.html](https://nim-lang.org/docs/tut3.html)

- Nim for
  - the C programmer: [https://github.com/nim-lang/Nim/wiki/Nim-for-C-programmers](https://github.com/nim-lang/Nim/wiki/Nim-for-C-programmers)
  - Python programmer: [https://github.com/nim-lang/Nim/wiki/Nim-for-Python-Programmers](https://github.com/nim-lang/Nim/wiki/Nim-for-Python-Programmers)

Further resources are collected at:
- [https://nim-lang.org/learn.html](https://nim-lang.org/learn.html)

### Compiler configuration

- Compiler User Guide: [https://nim-lang.org/docs/nimc.html](https://nim-lang.org/docs/nimc.html)

### Style Guide

- [https://nim-lang.org/docs/nep1.html](https://nim-lang.org/docs/nep1.html)
