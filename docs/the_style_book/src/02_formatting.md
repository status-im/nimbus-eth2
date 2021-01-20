# Formatting

<!-- toc -->

## Style

We follow [NEP-1](https://nim-lang.org/docs/nep1.html) for style matters, including naming, capitalization etc.

## Naming conventions

* `Ref` for `ref object` types, which have surprising semantics (see below)
    * `type XxxRef = ref Xxx`
    * `type XxxRef = ref object ...`
* `func init(T: type Xxx, params...): T` for "constructors"
* `func new(T: type XxxRef, params...): T` for "constructors" of `ref object` types
* `XxxError` for exceptions inheriting from `CatchableError`
* `XxxDefect` for exceptions inheriting from `Defect`

## Practical notes

* When porting python code, we sometimes prefer python style naming
* We do not use `nimpretty` - as of writing (nim 1.2), it is not stable enough for daily use:
    * can break working code
    * naive formatting algorithm
