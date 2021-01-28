# Tooling

<!-- toc -->

## Build system

We use a build system with `make` and `git` submodules. The long term plan is to move to a dedicated package and build manager once one becomes available.

### Pros

* Reproducible build environment
* Fewer disruptions due to mismatching versions of compiler and dependencies

### Cons

* Increased build system complexity with tools that may not be familiar to `nim` developers
* Build system dependencies hard to use on Windows and constrained environments

### nimble

We do not use `nimble`, due to the lack of build reproducibility and other team-oriented features. We sometimes provide `.nimble` packages but these may be out of date and/or incomplete.

## Dependency management

We track dependencies using `git` submodules to ensure a consistent build environment for all development. This includes the Nim compiler, which is treated like just another dependency - when checking out a top-level project, it comes with an `env.sh` file that allows you to enter the build environment, similar to python `venv`.

When working with upstream projects, it's sometimes convenient to _fork_ the project and submodule the fork, in case urgent fixes / patches are needed. These patches should be passed on to the relevant upstream.

### Pros

* Reproducible build environment ensures that developers and users talk about the same code
    * dependencies must be audited for security issues
* Easier for community to understand exact set of dependencies
* Fork enables escape hatch for critical issues

### Cons

* Forking incurs overhead when upgrading
* Transitive dependencies are difficult to coordinate
* Cross-project commits hard to orchestrate

### Practical notes

* All continuous integration tools build using the same Nim compiler and dependencies
* When a `Nim` or other upstream issue is encountered, consider project priorities:
  * Use a work-around, report issue upstream and leave a note in code so that the work-around can be removed when a fix is available
  * Patch our branch after achieving team consensus

## Nim version

We support a single Nim version that is upgraded between release cycles of our own projects. Individual projects and libraries may choose to support multiple Nim versions, though this involves significant overhead.

### Pros

* Nim `devel` branch, as well as feature and bugfix releases often break the codebase due to subtle changes in the language and code generation which are hard to diagnose - each upgrade requires extensive testing
* Easier for community to understand exact set of dependencies
* Balance between cutting edge and stability
* Own branch enables escape hatch for critical issues

### Cons

* Work-arounds in our code for `Nim` issues add technical debt
* Compiler is rebuilt in every clone

### Practical notes

* Following Nim `devel`, from experience, leads frequent disruptions as "mysterious" issues appear
* To support multiple Nim versions in a project, the project should be set up to run CI with all supported versions

## Editors

* Most developers use `vscode` with the [Nim plugin](https://marketplace.visualstudio.com/items?itemName=kosz78.nim)
  * To start `vscode` with the correct Nim compiler, run it with `./env.sh code`
  * Run nim files with `F6`
  * Suggestions, goto and similar features mostly work, but sometimes hang
    * You might need to `killall nimsuggest` occasionally
* Sublime text and `vim` are other popular choices

## Debugging

* Debugging can be done with `gdb`
  * Follow the [C/C++ guide](https://code.visualstudio.com/docs/cpp/config-linux) for setting it up in `vscode`
  * pass `--opt:none --debugger:native` to disable optimizations and enable debug symbols

## Profiling

* Linux: `perf`
* Anywhere: [vtune](https://software.intel.com/content/www/us/en/develop/tools/oneapi/components/vtune-profiler.html)

## Code tricks

* Find out where a function is used: temporarily mark it `{.deprecated.}`
