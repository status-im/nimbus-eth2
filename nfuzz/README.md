# Introduction

`libnfuzz` is a wrapper library that exports to C, a set of fuzzing test cases
written in Nim and making use of nim-beacon-chain.


# Building

To build the wrapper library (for more details follow first the instructions from
[nim-beacon-chain](../README.md)):

```bash
git clone https://github.com/status-im/nim-beacon-chain.git
cd nim-beacon-chain
make
# static library
make libnfuzz.a
# dynamic loaded library
make libnfuzz.so
```

Default, the library is build with the `minimal` config. To select a specific config you can instead run:
```bash
# build with mainnet config
make libnfuzz.a NIMFLAGS="-d:const_preset=mainnet"
```

For the library to be useful for fuzzing with libFuzzer (e.g. for
integration with [beacon-fuzz](https://github.com/sigp/beacon-fuzz)) we can pass
additional Nim arguments, e.g.:

```bash
make libnfuzz.a NIMFLAGS="--cc:clang --passC:'-fsanitize=fuzzer-no-link' --passL='-fsanitize=fuzzer'"
```
To disable BLS verification on deserialization of SSZ objects add `-d:ssz_testing` to the NIMFLAGS.

Other useful options might include: `--clang.path:<path>`, `--clang.exe:<exe>`, `--clang.linkerexe:<exe>`, `-d:const_preset=mainnet`

It might also deem useful to lower the log level, e.g. by adding `-d:chronicles_log_level=fatal`.

# Usage
There is a `libnfuzz.h` file provided for easy including in C or C++ projects.

It is most important that before any of the exported tests are called, the
`NimMain()` call is done first. Additionally, all following library calls need
to be done from the same thread as from where the original `NimMain()` call was
done.
