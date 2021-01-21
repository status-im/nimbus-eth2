# Formatting

<!-- toc -->

## Style

We strive to follow [NEP-1](https://nim-lang.org/docs/nep1.html) for style matters, including naming, capitalization, 80-character limit etc. Common places where deviations happen include:

* Code based on external projects
    * Wrappers / FFI
    * Implementations of specs that have their own naming convention
    * Ports from other languages
* Small differences due to manual formatting
* Aligned block / parameter / comment indents that require reformatting many lines to accomodate a small change - these are tedious to maintain, thus fixed indents (instead of indents based on identifiers) are allowed / common

## Naming conventions

* `Ref` for `ref object` types, which have surprising semantics (see below)
    * `type XxxRef = ref Xxx`
    * `type XxxRef = ref object ...`
* `func init(T: type Xxx, params...): T` for "constructors"
* `func new(T: type XxxRef, params...): T` for "constructors" of `ref object` types
* `XxxError` for exceptions inheriting from `CatchableError`
* `XxxDefect` for exceptions inheriting from `Defect`

## Practical notes

* We do not use `nimpretty` - as of writing (nim 1.2), it is not stable enough for daily use:
    * Can break working code
    * Naive formatting algorithm
* We do not make use of Nim's "flexible" identifier names - all uses of an identifier should match the declaration in capitalization and underscores
