---
title: "SSZ (De)Serialization & Tree hashing"
code_owner: "Zahary Karadjov (zah)"
round: "Audit round 2"
category: "Network Core Audit"
repositories: "nim-beacon-chain"
---

Relevant modules:

SSZ spec implementation:
https://github.com/status-im/nim-beacon-chain/tree/master/beacon_chain/ssz

Spec:
https://github.com/ethereum/eth2.0-specs/blob/dev/ssz/simple-serialize.md

Lower-level layers:

* Nim-serialization
https://github.com/status-im/nim-serialization/
Implements compile-time reflection responsible for operations such as "List all serializable fields of an object", defines a generic protocol and a set of extensibility points (overloadable functions) that can be used to provide custom serialization for certain types.

May be sensitive to bugs in the Nim compiler related to generic programming.

* Nim-FastStreams
https://github.com/status-im/nim-faststreams/
Defines low-level interfaces for working with various synchronous and asynchronous input streams.

The SSZ implementation is tested against the official Eth2 test suite here:
https://github.com/status-im/nim-beacon-chain/blob/master/tests/official/test_fixture_ssz_consensus_objects.nim
https://github.com/status-im/nim-beacon-chain/blob/master/tests/official/test_fixture_ssz_generic_types.nim

Run the tests with:
nim c -r tests/official/test_fixture_ssz_consensus_objects.nim

Also, with some basic fuzzing tests here:
https://github.com/status-im/nim-beacon-chain/blob/master/scripts/run_ssz_fuzzing_test.nims
https://github.com/status-im/nim-beacon-chain/blob/master/tests/fuzzing/ssz_fuzzing.nim

The fuzzing tests can be launched with:

nim scripts/run_ssz_fuzzing_test.nims Attestation

or

nim scripts/run_ssz_fuzzing_test.nims --fuzzer:honggfuz Attestation
