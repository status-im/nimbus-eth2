# Introduction

!!! warning
    This auditors' handbook is frozen and obsolete; the [Nim language manual](https://nim-lang.org/docs/manual.html) alongside [other Nim documentation](https://nim-lang.org/documentation.html), [Status Nim style guide](https://status-im.github.io/nim-style-guide/), [Chronos guides](https://github.com/status-im/nim-chronos/blob/master/docs/src/SUMMARY.md), and [Nim by Example](https://nim-by-example.github.io/getting_started/) supercede it.

The Nimbus Nim-Beacon-Chain (NBC) project is an implementation of the [Ethereum 2 Beacon Chain specification](https://github.com/ethereum/consensus-specs) in the [Nim programming language](https://nim-lang.org/).

The Auditors' Handbook aims to be provide a comprehensive introduction to:
- The Nim programming language, as used in the project.
- The NBC project.
- The dependencies of the project.

A particular focus will be given to features related to safety, correctness, error handling, testing, fuzzing, or inspecting Nim code.

One of the major highlights of Nim is that it compiles to C or C++ before compiling to native code. All techniques available to audit C code can be used to audit Nim.

The dependencies NBC rely on are detailed per audit phase in the [build system and dependencies](03.2_build_system_and_dependencies.md) section.
