# Introduction

`ncli` is a set of low level / debugging tools to interact with the nimbus [beacon chain specification](https://github.com/ethereum/consensus-specs/tree/dev/specs) implementation, similar to [zcli](https://github.com/protolambda/zcli). With it, you explore SSZ, make state transitions and compute hash tree roots.

# Tools

* transition: Perform state transition given a pre-state and a block to apply (both in SSZ format)
* hash_tree_root: Print tree root of an SSZ object
* pretty: Pretty-print SSZ object as JSON

# Building

Follow the instructions from [nimbus-eth2](../README.md)

```bash
git clone https://github.com/status-im/nimbus-eth2.git
cd nimbus-eth2
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
