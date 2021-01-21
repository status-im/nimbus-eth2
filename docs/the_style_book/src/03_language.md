# Language features

Nim is a language that organically has grown to contain many advanced features and constructs. These features allow you to express your intent with great creativity, but often come with significant stability, simplicity and correctness caveats when combined.

<!-- toc -->

## Import, export

[Manual](https://nim-lang.org/docs/manual.html#modules-import-statement)

`import` a minimal set of modules using explicit paths. `export` all modules whose types appear in public symbols of the current module. Prefer specific imports. Avoid `include`.

```nim
# Group by std, external then internal imports
import
  # Standard library imports are prefixed with `std/`
  std/[options, sets],
  # use full name for "external" dependencies (those from other packages)
  package/[a, b],
  # use relative path for "local" dependencies
  ./c, ../d

# export modules whose types are used in public symbols in the current module
export options
```

### Practical notes

Modules in Nim share a global namespace, both for the module name itself and for all symbols contained therein - because of this, it happens that your code might break because a dependency introduces a module or symbol with the same name - using prefixed imports (relative or package) helps mitigate some of these conflicts.

Because of overloading and generic catch-alls, the same code can behave differently depending on which modules have been imported and in which order - reexporting modules that are used in public symbols helps avoid some of these differences.

## Macros

[Manual](https://nim-lang.org/docs/manual.html#macros)

Be judicious in macro usage - prefer more simple constructs.
Avoid generating public API functions with macros.

### Pros

* Concise domain-specific languages precisely convey the central idea while hiding underlying details
* Suitable for cross-cutting libraries such as logging and serialization, that have a simple public API
* Prevent repetition, sometimes

### Cons

* Easy to write, hard to understand
  * Require extensive knowledge of the `Nim` AST
  * Code-about-code requires tooling to turn macro into final execution form, for audit and debugging
  * Unintended macro expansion costs can surprise even experienced developers
* Unsuitable for public API
  * Nowhere to put per-function documentation
  * Tooling needed to discover API - return types, parameters, error handling
* Obfuscated data and control flow
* Poor debugging support
* Surprising scope effects on identifier names

### Practical notes

* Consider a more specific, non-macro version first
* Use a difficulty multiplier to weigh introduction of macros:
  * Templates are 10x harder to understand than plain code
  * Macros are 10x harder than templates, thus 100x harder than plain code
* Write as much code as possible in templates, and glue together using macros

See also: [macro defense](https://github.com/status-im/nimbus-eth2/wiki/The-macro-skeptics-guide-to-the-p2pProtocol-macro)

## `ref object`

Avoid `ref object`, except for "handle" types that manage a resource, where shared ownership is intended, in reference-based data structures (trees, linked lists).

```nim
# prefer explicit ref modifiers at usage site
func f(v: ref Xxx) = discard
let x: ref Xxx = new Xxx

# Consider using naming convention with `ref object`
type XxxRef = ref object
  # ...
```

### Pros

* `ref object` types useful to prevent unintended copies
* limit risk of accidental stack overflow for large types
* Garbage collector simplifies some algorithms

### Cons

* `ref object` types have surprising semantics - the meaning of basic operations like `=` changes
* shared ownership leads to resource leaks and data races
* `nil` references cause runtime crashes
* semantic differences not visible at call site
* always mutable - no way to express immutability
* Cannot be stack-allocated
* Hard to emulate value semantics
* Prone to leaks

### Notes

`XxxRef = ref object` is a syntactic shortcut that hides the more explicit `ref Xxx` where the type is used - by explicitly spelling out `ref`, readers of the code become aware of the alternative reference / shared ownership semantics, which generally allows a deeper understanding of the code without having to look up the type declaration.

## Heap / garbage collected memory

Prefer to use stack-based and statically sized data types in core/low-level libraries.
Use heap allocation in glue layers.

Avoid `alloca`.

```
func init(T: type Yyy, a, b: int): T = ...

# Heap allocation as a local decision
let x = (ref Xxx)(
  field: Yyy.init(a, b) # In-place initialization using RVO
)
```

### Pros

* RVO can be used for "in-place" initialization of value types
* Better chance of reuse on embedded systems
  * https://barrgroup.com/Embedded-Systems/How-To/Malloc-Free-Dynamic-Memory-Allocation
  * http://www.drdobbs.com/embedded-systems/embedded-memory-allocation/240169150
  * https://www.quora.com/Why-is-malloc-harmful-in-embedded-systems
* Allows consumer of library to decide on memory handling strategy
    * It's always possible to turn plain type into `ref`, but not the other way around

### Cons

* Stack space limited - large types on stack cause hard-to-diagnose crashes
* Hard to deal with variable-sized data correctly
* `alloca` has confusing semantics that easily cause stack overflows

## Inline functions

Avoid using explicit `{.inline.}` functions.

### Pros

* Sometimes have performance advantages

### Cons

* Adds clutter to function definitions
* Larger code size, longer compile times
* Prevents contextually driven optimization tradeoffs in speed vs size

### Practical notes

* Compilers can use contextual information to balance inlining
* LTO achieves the same end result without the cons

## Converters

[Manual](https://nim-lang.org/docs/manual.html#converters)

Avoid using converters.

### Pros

* Implicit conversions lead to low visual overhead of converting types

### Cons

* Surprising conversions lead to ambiguous calls:
  ```nim
  converter toInt256*(a: int{lit}): Int256 = a.i256
  if stringValue.len > 32:
    ...
  ```
  ```
  Error: ambiguous call; both constants.>(a: Int256, b: int)[declared in constants.nim(76, 5)] and constants.>(a: UInt256, b: int)[declared in constants.nim(82, 5)] match for: (int, int literal(32))
  ```

## Object initialization

Prefer `Xxx(x: 42, y: Yyy(z: 54))` style, or if type has an `init` function, `Type.init(a, b, c)`.

```nim
# `init` functions serve as constructors
func init(T: type Xxx, a, b: int): T = T(
  x: a,
  y: OtherType(s: b) # Prefer Type(field: value)-style initialization
)

let m = Xxx.init(1, 2)

# For ref types, name the constructor `new`:
func new(T: type XxxRef): T = ...
```

### Pros

* Correct order of initialization enforced by compiler / code structure
* Dedicated syntax constructs a clean instance resetting all fields
* Possible to build static analysis tools to detect uninitialized fields
* Works for both `ref` and non-`ref` types

### Cons

* Sometimes inefficient compared to updating an existing `var` instance, since all fields must be re-initialized

### Practical notes

* Avoid using `result` (see below) or `var instance: Type` which disable several compiler diagnostics

## `result` return

Avoid using `result` for returning values.

Prefer expression-based return or explicit `return` keyword with a value

### Pros

* Some code uses it, recommended by NEP-1
* Saves a line of code avoiding an explicit `var` declaration
* Accumulation-style functions that gradually build up a return value gain consistency

### Cons

* Disables compiler diagnostics for code branches that forget to set result
* Risk of using partially initialized instances due to `result` being default-initialized
    * For `ref` types, `result` starts out as `nil` which accidentally might be returned
    * Helpers may accidentally use `result` before it was fully initialized
    * Async/await using result prematurely due to out-of-order execution
* Partially initialized instances lead to exception-unsafe code where resource leaks happen
    * RVO causes observable stores in the left-hand side of assignments when exceptions are raised after partially modifying `result`
* Confusing to people coming from other languages
* Confusing semantics in templates

### Practical notes

Nim has 3 ways to assign a return value to a function: `result`, `return` and "expressions".

Of the three:

* "expression" returns guarantee that all code branches produce one (and only one) value to be returned
* explict `return` with a value make explicit what value is being returned in each branch.
* `result`, together with indent-based code-flow, makes it difficult to visually ascertain which code paths are missing a return value, or overwrite the return value of a previous branch.

Multiple security issues, `nil` reference crashes and wrong-init-order issues have been linked to the use of `result` and lack of assignment in branches.

In general, the use of accumulation-style initialization is discouraged unless necessary by the data type - see [Variable initialization](#variable-initialization)

## Variable declarations

Use the most restrictive of `const`, `let` and `var` that the situation allows.

```nim
# Group related variables
let
  a = 10
  b = 20
```

### Practical notes

`const` and `let` each introduce compile-time constraints that help limit the scope of bugs that must be considered when reading and debugging code.

## Variable initialization

Prefer expressions to initialize variables and return values

```
let x =
  if a > 4: 5
  else: 6

func f(b: bool): int =
  if b: 1
  else: 2

# Avoid - `x` is not guaranteed to be initialized by all branches and in correct order (for composite types)
var x: int
if a >4: x = 5
else: x = 6
```

### Pros

* Stronger compile-time checks
* Lower risk of uninitialized variables even after refactoring

### Cons

None

## Functions and procedures

Prefer `func` - use `proc` when side effects cannot conveniently be avoided.

## Callbacks and closures

```nim
# By default, Nim assumes closures may raise any exception and are not gcsafe
# By annotating the callback with raises and gcsafe, the compiler ensures that
# any functions assigned to the closure fit the given constraints
type Callback = proc(...) {.raises: [Defect], gcsafe.}
```

### Practical notes

* When calling an un-annotated closure / callback, the compiler does not know if it potentially raises or contains gcunsafe code, thus assumes the worst case
* Deduced excpetion and gcsafe information is passed up the call chain

## Binary data

Use `byte` to denote binary data. Use `seq[byte]` for dynamic byte arrays.

Avoid `string` for binary data. If stdlib returns strings, [convert](https://github.com/status-im/nim-stew/blob/76beeb769e30adc912d648c014fd95bf748fef24/stew/byteutils.nim#L141) to `seq[byte]` as early as possible

### Pros

* Explicit type for binary data helps convey intent

### Cons

* `char` and `uint8` are common choices often seen in `Nim`
* hidden assumption that 1 byte == 8 bits
* language still being developed to handle this properly - many legacy functions return `string` for binary data
  * [Crypto API](https://github.com/nim-lang/Nim/issues/7337)

### Practical notes

* [stew](https://github.com/status-im/nim-stew) contains helpers for dealing with bytes and strings

## Workflow

### Contributing

For style and other trivial fixes, commit straght to master
For small ideas, use a PR
For big ideas, use an RFC issue

## Useful resources

* [The Nimbus auditor book](https://nimbus.guide/auditors-book/) goes over security concerns of Nim features in detail
