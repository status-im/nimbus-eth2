# Introduction

`ncli` is a set of low level / debugging tools to interact with the nimbus [beacon chain specification](https://github.com/ethereum/eth2.0-specs/tree/dev/specs) implementation, simliar to [zcli](https://github.com/protolambda/zcli). With it, you explore SSZ, make state transitions and compute hash tree roots.

# Tools

* transition: Perform state transition given a pre-state and a block to apply (both in SSZ format)
* hash_tree_root: Print tree root of an SSZ object
* pretty: Pretty-print SSZ object as JSON

# Building

Follow the instructions from [nim-beacon-chain](../README.md)

```bash
git clone https://github.com/status-im/nim-beacon-chain.git
cd nim-beacon-chain
make
```

# Usage

```
# Build with minimal config
../env.sh nim c -d:const_preset=minimal ncli_transition
# Build with mainnet config
../env.sh nim c -d:const_preset=mainnet ncli_transition

# Run..
./ncli_transition --help
```
