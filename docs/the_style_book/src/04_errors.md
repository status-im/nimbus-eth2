# Error handling

Error handling in Nim is a subject under constant re-evaluation - similar to C++, several paradigms are supported leading to confusion as to which one to choose.

In part, the confusion stems from the various contexts in which nim can be used: when executed as small, one-off scripts that can easily be restarted, exceptions allow low visual overhead and ease of use.

When faced with more complex and long-running programs where errors must be dealt with as part of control flow, the use of exceptions can directly be linked to issues like resource leaks, security bugs and crashes.

Likewise, when preparing code for refactoring, the compiler offers little help in exception-based code: although raising a new exception breaks ABI, there is no corresponding change on in the API meaning that changes deep inside dependencies silently break dependent code until the issue becomes apparent at runtime, often under exceptional circumstances.

A final note is that although exceptions may have been used sucessfully in some languages, these languages typically offer complementary features that help manage the complexities introduced by exceptions - RAII, mandatory checking of exceptions etc - this has yet to be developed for Nim.

Because of the controversies and changing landscape, the preference for Status projects is to avoid the use exceptions unless specially motivated, if only to maintain consistency and simplicity.

<!-- toc -->

## General

Prefer `bool`, `Opt` or `Result` to signal failure outcomes explicitly.

Prefer the use of `Result` when multiple failure paths exist and the calling code might need to differentiate between them.

Raise `Defect` to signal panics such as logic errors or preconditions being violated.

Make error handling explicit and visible at call site using explicit control flow (`if`, `try`, `results.?`).

Handle errors at each abstraction level, avoiding spurious abstraction leakage.

Isolate legacy code with explicit exception handling, converting the errors to `Result` or handling them locally, as appropriate.

```nim
# Annotate all modules with a top-level `{.push raises: [Defect].}`
{.push raises: [Defect].}

import stew/results
export results # Re-export modules used in public symbols

# Use `Result` to propagate additional information expected errors
# See `Result` section for specific guidlines for errror type
func f*(): Result[void, cstring]

# In special cases that warrant the use of exceptions, list these explicitly using the `raises` pragma.
func parse(): Type {.raises: [Defect, ParseError]}
```

See also [Result](04_libraries.md#result) for more recommendations about `Result`.

See also [Error handling helpers](https://github.com/status-im/nim-stew/pull/26) in stew that may change some of these guidelines.

## Exceptions

In general, prefer [explicit error handling mechanisms](#general).

Annotate each module with a top-level `{.push raises: [Defect].}`.

Use explicit `{.raises.}` annotation for each function in public API.

When using exceptions, use `raises` annotations (checked exceptions).

Raise `Defect` to signal panics and situations that the code is not prepared to handle.

```nim
`{.push raises: [Defect].}` # Always at start of module

# Inherit from CatchableError and name XxxError
type MyLibraryError = object of CatchableError

# Raise Defect when panicking - this crashes the application (in different ways
# depending on Nim version and compiler flags) - name `XxxDefect`
type SomeDefect = object of Defect

# Use hierarchy for more specific errors
type MySpecificError = object of MyLibraryError

# Explicitly annotate functions with raises
func f() {.raises: [Defect, MySpecificError]} = discard

# Isolate code that may generate exceptions using expression-based try:
let x =
  try: ...
  except MyError as exc: ... # use the most specific error kind possible

# Be careful to catch excpetions inside loops, to avoid partial loop evaluations:
for x in y:
  try: ..
  except MyError: ..

# Provide contextual data when raising specific errors
raise (ref MyError)(msg: "description", data: value)
```

### Pros

* Used by `Nim` standard library
* Good for quick prototyping without error handling
* Good performance on happy path without `try`
  * Compatible with RVO

### Cons

* Poor readability - exceptions not part of API / signatures by default
    * Have to assume every line may fail
* Poor maintenance / refactoring support - compiler can't help detect affected code because they're not part of API
* Nim exception hierarchy unclear and changes between versions
    * the distinction between `Exception`, `CatchableError` and `Defect` is inconsistently implemented
        * [Exception hierarchy RFC not being implemented](https://github.com/nim-lang/Nim/issues/11776)
    * `Defect` is [not correctly tracked]((https://github.com/nim-lang/Nim/issues/12862))
    * Nim 1.4 further weakens compiler analysis around `Defect`(https://github.com/nim-lang/Nim/pull/13626)
* Without translation, exceptions leak information between abstraction layers
* Writing exception-safe code in Nim unpractical due to missing critical features (compared to C++)
    * no RAII - resources often leak in the presence of exceptions
    * destructors incomplete / unstable and thus not usable for safe EH
        * no constructors, thus no way to force particular object states at construction
    * `ref` types incompatible with destructors, even if they worked
* Poor performance of error path
    * Several heap allocations for each Exception (exception, stack trace, string)
    * Expensive stack trace
* Poor performance on happy path
    * every `try` and `defer` has significant performance overhead due to `setjmp` exception handling implementation

### Practical notes

The use of exceptions in some modules has significantly contributed to resource leaks, deadlocks and other difficult bugs. The various exception handling proposals aim to alleviate some of the issues but have not found sufficient grounding in the Nim community to warrant the language changes necessary to proceed.

A notable exception to the guideline is `chronos` and `async`/`await` transformations that lack support for propagating checked exception information. Several bugs and implementation issues exist in the exception handling transformation employed by `async`.

### Open questions

* Should a hierarchy be used?
    * Why? It's rare that calling code differentiates between errors
    * What to start the hierarchy with? Unclear whether it should be a global type (like `CatchableError` or `ValueError`, or a module-local type
* Should exceptions be translated?
    * Leaking exception types between layers means no isolation, joining all modules in one big spaghetti bowl
    * Translating exceptions has high visual overhead, specially when hierachy is used - not practical, all advantages lost
* Should `raises` be used?
    * Equivalent to `Result[T, SomeError]` but lacks generics
    * Additive - asymptotically tends towards `raises: [CatchableError]`, losing value unless exceptions are translated locally
    * No way to transport accurate raises type information across Future/async/generic code boundaries - no `raisesof` equivalent of `typeof`

### Background

* [Stew EH helpers](https://github.com/status-im/nim-stew/pull/26) - Helpers that make working with checked exceptions easier
* [Nim Exception RFC](https://github.com/nim-lang/Nim/issues/8363) - seeks to differentiate between recoverable and unrecoverable errors
* [Zahary's handling proposal](https://gist.github.com/zah/d2d729b39d95a1dfedf8183ca35043b3) - seeks to handle any kind of error-generating API
* [C++ proposal](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2018/p0709r0.pdf) - After 25 years of encouragement, half the polled C++ developers continue avoiding exceptions and Herb Sutter argues about the consequences of doing so
* [Google](https://google.github.io/styleguide/cppguide.html#Exceptions) and [llvm](https://llvm.org/docs/CodingStandards.html#id22) style guides on exceptions

## Status codes

Avoid status codes.

```nim

type StatusCode = enum
  Success
  Error1
  ...

func f(output: var Type): StatusCode
```

### Pros

* Interop with `C`

### Cons

* `output` undefined in case of error
* verbose to use, must first declare mutable variable then call function and check result - mutable variable remains in scope even in "error" branch leading to bugs

## Practical notes

Unlike "Error Enums" used with `Result`, status codes mix "success" and "error" returns in a single enum, making it hard to detect "successful" completion of a function in a generic way.

## Callbacks

See [language section on callbacks](03_language.md#callbacks-closures-and-forward-declarations)
