# Summary

!!! warning
    This auditors' handbook is frozen and obsolete; the [Nim language manual](https://nim-lang.org/docs/manual.html) alongside [other Nim documentation](https://nim-lang.org/documentation.html), [Status Nim style guide](https://status-im.github.io/nim-style-guide/), [Chronos guides](https://github.com/status-im/nim-chronos/blob/master/docs/src/SUMMARY.md), and [Nim by Example](https://nim-by-example.github.io/getting_started/) supercede it.

- [Introduction](01_introduction.md)
- [The Nim Programming Language](02_the_Nim_programming_language.md)
  - [Nim routines, procedures, functions, templates, macros](02.1_nim_routines_proc_func_templates_macros.md)
    - [Operators, bit manipulation](02.1.1_operators_bit_manipulation.md)
    - [Closure iterators](02.1.4_closure_iterators.md)
  - [Datatypes: value, ref, ptr](02.2_stack_ref_ptr_types.md)
    - [Casting and low-level memory representation](02.2.2_casting_and_low_level_memory_representation.md)
    - [Memory Management and Garbage Collection](02.2.3_memory_management_gc.md)
    - [Generic types & static types](02.2.4_generics_types_static_types.md)
    - [Arrays, openarrays, strings, C-strings](02.2.5_arrays_openarrays_strings_cstring.md)
  - [Correctness: distinct, mutability, effects, exceptions](02.3_correctness_distinct_mutability_effects_exceptions.md)
  - [Debugging Nim, sanitizers, fuzzers](02.4_debugging_Nim_sanitizers_fuzzers.md)
  - [Foreign lang interop: C and C++](02.5_foreign_lang_to_from_interop.md)
  - [Nim threat model](02.8_Nim_threat_model.md)
  - [Nim FAQ](02.10_Nim_FAQ.md)
- [Nimbus NBC - The Nim-Beacon-Chain](03_nbc_nimbus_beacon_chain.md)
  - [Build system and dependencies](03.2_build_system_and_dependencies.md)
  - [Threat model](03.5_the_threat_model.md)
- [Serialization](04_serialization.md)
- [Async/Await with Chronos](05_async_with_chronos.md)
- [Cryptography](06_cryptography_and_rng.md)
- [Ethereum Networking](07_nim-eth.md)

<!-- Not fleshed out, out of line because mdbook bug -->

<!-- - [Pointer manipulation](02.1.2_pointer_manipulation.md) -->
<!-- - [Emitting raw C or Assembly code](02.1.3_emitting_raw_C_assembly_code.md) -->

<!-- - [Builtin types](02.2.1_builtin_types.md) -->

<!-- - [Runtime types: Variants & Object-Oriented Programming](02.2.6_runtime_types_variants_oop.md) -->
<!-- - [Compile-time Evaluation](02.2.7_compiletime_evaluation.md) -->

<!-- - [Nim standard library use in Nimbus](02.9_Nim_stdlib_use_in_nimbus.md) -->
