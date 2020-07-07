# Serialization

Serialization used in production is done by the library [nim-serialization](https://github.com/status-im/nim-serialization).

This library exposes a set of common routines that are format agnostic.

The library only serialize to and from statically defined types. The macros transformation generates tight code specialized to the datatypes.

_This may become particularly valuable for WASM code generation and smart contract in general as execution cost depends on the number of instructions._

Serialization formats are implemented in specialized libraries such as:
- [nim-json-serialization](https://github.com/status-im/nim-json-serialization)
- [nim-protobuf-serialization](https://github.com/status-im/nim-protobuf-serialization)
- [SSZ (SimpleSerialize)](https://github.com/status-im/nim-beacon-chain/tree/master/beacon_chain/ssz)

## Serialization for networking

## Serialization for ETH2 core

## Serialization for Validator core

## Serialization used in testing

Serialization libraries for testing are out of audit scope and included for completeness.

For testing we also use [nimYAML](https://github.com/flyx/NimYAML) to parse Ethereum Specification test files.
