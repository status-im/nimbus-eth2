# Libraries

The libraries section contains guidelines for libraries and modules frequently used in the codebase.

<!-- toc -->

## Results

[Manual](https://github.com/status-im/nim-stew/blob/master/stew/results.nim#L19)

Use `Result` to document all outcomes of functions.

Use `cstring` errors to provide diagnostics without expectation of error differentiation.

Use `enum` errors when error kind matters.

Use complex types when additional error information needs to be included.

Use `Opt` (`Result`-based `Option`) for simple functions that fail only in trivial ways.

```
# Stringly errors - the cstring is just for information and
# should not be used for comparisons! The expectation is that
# the caller doesn't have to differentiate between different
# kinds of errors and uses the string as a print-only diagnostic.
func f(): Result[int, cstring] = ...

# Calling code acts on error specifics - use an enum
func f2(): Result[int, SomeEnum] = ...
if f2.isErr and f2.error == SomeEnum.value: ...

# Transport exceptions - Result has special support for this case
func f3(): Result[int, ref SomeError] = ...
```

### Pros

* Give equal consideration to normal and error case
* Easier control flow vulnerability analysis
* Good for "binary" cases that either fail or not
* No heap allocations for simple errors

### Cons

* Visual overhead and poor language integration in `Nim` - ugly `if` trees grow
* Nim compiler generates ineffient code for complex types due to how return values are 0-intialized
* lack of pattern matching makes for inconvenient code
* standard library raises many exceptions, hard to use cleanly

### Practical notes

* When converting modules, isolate errors from legacy code with `try/except`
  * common helpers may be added at some point to deal with third-party dependencies that are hard to change - see `stew/shims`

## Hex output

Print hex output in lowercase. Accept upper and lower case.

### Pros

* Single case helps tooling
* Arbitrary choice, aim for consistency

### Cons

* No community consensus - some examples in the wild use upper case

### Practical notes

[byteutils](https://github.com/status-im/nim-stew/blob/76beeb769e30adc912d648c014fd95bf748fef24/stew/byteutils.nim#L129) contains a convenient hex printer.

## Wrappers

Prefer native `Nim` code when available.

`C` libraries and libraries that expose a `C` API may be used (including `rust`, `C++`).

Avoid `C++` libraries.

Prefer building the library on-the-fly from source using `{.compile.}`. Pin the library code using a submodule or amalgamation.

### Pros

* Wrapping existing code can improve time-to-market for certain features
* Maintenance is shared with upstream
* Build simplicity is maintained when `{.compile.}` is used

### Cons

* Often leads to unnatural API for `Nim`
* Constrains platform support
* Nim and `nimble` tooling poorly supports 3rd-party build systems making installation difficult
* Nim `C++` support incomplete
  * Less test suite coverage - most of `Nim` test suite uses `C` backend
  * Many core `C++` features like `const`, `&` and `&&` difficult to express - in particular post-`C++11` code has a large semantic gap compared to Nim
  * Different semantics for exceptions and temporaries compared to `C` backend
  * All-or-nothing - can't use `C++` codegen selectively for `C++` libraries
* Using `{.compile.}` increases build times, specially for multi-binary projects - use judiciously for large dependencies

### Practical notes

* Consider tooling like `c2nim` and `nimterop` to create initial wrapper
* Generate a `.nim` file corresponding to the `.h` file of the C project
  * preferably avoid the dependency on the `.h` file (avoid `{.header.}` directives unless necessary)
* Write a separate "raw" interface that only imports `C` names and types as they're declared in `C`, then do convenience accessors on the Nim side
  * Name it `xxx_abi.nim`
* To use a `C++` library, write a `C` wrapper first
  * see `llvm` for example
* When wrapping a `C` library, consider ABI, struct layout etc

### Examples

* [nim-secp256k1](https://github.com/status-im/nim-secp256k1)
* [nim-sqlite](https://github.com/arnetheduck/nim-sqlite3-abi)
* [nim-bearssl](https://github.com/status-im/nim-bearssl/)
* [nim-blscurve](https://github.com/status-im/nim-blscurve/)

## Standard library usage

Use the Nim standard library judiciously. Prefer smaller, separate packages that implement similar functionality, where available.

### Pros

* using components from the standard library increases compatibility with other Nim projects
* fewer dependencies in general

### Cons

* large, monolithic releases make upgrading difficult - bugs, fixes and improvements are released together causing upgrade churn
* many modules in the standard library are unmaintained and don't use state-of-the-art features of Nim
* long lead times for getting fixes and improvements to market
* often not tailored for specific use cases
* stability and backwards compatibility requirements prevent fixing poor and unsafe API

### Practical notes

Use the following stdlib replacements that offer safer API (allowing more issues to be detected at compile time):

* async -> chronos
* bitops -> stew/bitops2
* endians -> stew/endians2
* exceptions -> stew/results
* io -> stew/io2
* sqlite -> nim-sqlite3-abi
* streams -> nim-faststreams

## nim-stew

If similar libraries exist in nim stdlib and stew, prefer [stew](https://github.com/status-im/nim-stew)

### Pros

* `stew` solves bugs and practical API design issues in stdlib without having to wait for nim release
* Fast development cycle
* Allows battle-testing API before stdlib consideration (think boost)
* Encourages not growing nim stdlib further, which helps upstream maintenance

### Cons

* Less code reuse across community
* More dependencies that are not part of nim standard distribution

### Practical notes

`nim-stew` exists as a staging area for code that could be considered for future inclusion in the standard library or, preferably, a separate package, but has not yet been fully fleshed out as a separate and complete library.
